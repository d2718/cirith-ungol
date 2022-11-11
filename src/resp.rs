/*!
Mostly functions for writing `hyper::Response`s.
*/

use std::{
    ffi::OsStr,
    fmt::Debug,
    fs::{DirEntry, Metadata},
    io::{ErrorKind, Write},
    net::SocketAddr,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::Stdio,
    time::SystemTime,
};

use futures_util::{FutureExt, StreamExt};
use hyper::{
    header,
    header::{HeaderName, HeaderValue},
    Body, Method, Request, Response, StatusCode,
};
use smallvec::SmallVec;
use time::{
    format_description::{well_known::Rfc2822, FormatItem},
    macros::format_description,
    OffsetDateTime,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader, BufWriter},
    process::Command,
};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::{
    mime::{MIME_TYPES, OCTET_STREAM},
    SERVER,
};

static CANNED_HEAD: &str = include_str!("response_files/canned_head.html");
static CANNED_MIDDLE: &str = include_str!("response_files/canned_middle.html");
static CANNED_FOOT: &str = include_str!("response_files/canned_foot.html");
static CANNED_BASE_RESPONSE_LEN: usize =
    CANNED_HEAD.len() + CANNED_MIDDLE.len() + CANNED_FOOT.len();

static INDEX_HEAD: &str = include_str!("response_files/autoindex_head.html");
static INDEX_MIDDLE: &str = include_str!("response_files/autoindex_middle.html");
static INDEX_FOOT: &str = include_str!("response_files/autoindex_foot.html");
//static INDEX_BASE_RESPONSE_LEN: usize = INDEX_HEAD.len() + INDEX_MIDDLE.len() + INDEX_FOOT.len();

static INDEX_TIME_FMT: &[FormatItem] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

static R_403: (&str, &str) = (
    "Forbidden (403)",
    "<h1>Forbidden (403)<h1>
    <p>You are not permitted to access this resource.</p>",
);
static R_404: (&str, &str) = (
    "Not Found (404)",
    "<h1>Not Found (404)</h1>
    <p>There is no resource available at the URI you requested.</p>",
);
static R_405: (&str, &str) = (
    "Method Not Allowed (405)",
    "<h1>Method Not Allowed</h1>
    <p>The requested HTTP method may not be used with the requested URI.</p>",
);
static R_413: (&str, &str) = (
    "Payload Too Large (413)",
    "<h1>Payload Too Large (413)</h1>
    <p>The request you sent is too large.</p>",
);
static R_429: (&str, &str) = (
    "Too Many Requests (429)",
    "<h1>Too Many Requests (429)</h1>
    <p>Please exhibit a modicum of chill.</p>",
);
static R_500: (&str, &str) = (
    "Internal Server Error (500)",
    "<h1>Internal Server Error (500)</h1>
    <p>There was an error attempting to fetch the resource you requested.</p>",
);

pub fn canned_html_response<S>(code: S) -> Response<Body>
where
    S: TryInto<StatusCode> + Debug + Copy,
{
    log::trace!("canned_html_response( {:?} ) called.", &code);

    let mut code: StatusCode = match code.try_into() {
        Ok(code) => code,
        Err(_) => {
            log::error!("Unable to convert to StatusCode: {:?}", &code);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };

    let (title, contents) = match code {
        StatusCode::FORBIDDEN => R_403,
        StatusCode::NOT_FOUND => R_404,
        StatusCode::METHOD_NOT_ALLOWED => R_405,
        StatusCode::PAYLOAD_TOO_LARGE => R_413,
        StatusCode::TOO_MANY_REQUESTS => R_429,
        StatusCode::INTERNAL_SERVER_ERROR => R_500,
        x => {
            log::warn!(
                "resp::canned_html_response(): unsupported status code {:?}, using 500.",
                &x
            );
            code = StatusCode::INTERNAL_SERVER_ERROR;
            R_500
        }
    };

    let response_length = CANNED_BASE_RESPONSE_LEN + title.len() + contents.len();
    let mut v: Vec<u8> = Vec::with_capacity(response_length);

    v.write_all(CANNED_HEAD.as_bytes()).unwrap();
    v.write_all(title.as_bytes()).unwrap();
    v.write_all(CANNED_MIDDLE.as_bytes()).unwrap();
    v.write_all(contents.as_bytes()).unwrap();
    v.write_all(CANNED_FOOT.as_bytes()).unwrap();

    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
        .header(header::CONTENT_LENGTH, HeaderValue::from(response_length))
        .body(Body::from(v))
        .unwrap()
}

pub fn header_only<S>(code: S, mut addl_headers: Vec<(HeaderName, HeaderValue)>) -> Response<Body>
where
    S: TryInto<StatusCode> + Debug + Copy,
{
    log::trace!(
        "header_only( {:?}, [ {} add'l headers ] ) called.",
        &code,
        addl_headers.len()
    );

    let code: StatusCode = match code.try_into() {
        Ok(code) => code,
        Err(_) => {
            log::error!("Unable to convert StatusCode: {:?}", &code);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };

    let mut resp = Response::builder()
        .status(code)
        .body(Body::empty())
        .unwrap();

    for (name, val) in addl_headers.drain(..) {
        resp.headers_mut().insert(name, val);
    }

    resp
}

pub fn trace(req: Request<Body>) -> Result<Response<Body>, String> {
    log::trace!("trace( [ Request for {} ] ) called.", req.uri());

    let (parts, _) = req.into_parts();

    let mut body = format!(
        "{} {} {:?}\n",
        &parts.method,
        parts.uri.path(),
        &parts.version
    )
    .into_bytes();

    for (name, value) in parts.headers.iter() {
        body.write(name.as_str().as_bytes())
            .map_err(|e| format!("error writing header name: {}", &e))?;
        body.push(b':');
        body.push(b' ');
        body.write(value.as_bytes())
            .map_err(|e| format!("error writing header value: {}", &e))?;
        body.push(b'\r');
        body.push(b'\n');
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("message/http"),
        )
        .header(header::CONTENT_LENGTH, HeaderValue::from(body.len()))
        .body(Body::from(body))
        .map_err(|e| format!("error generating response: {}", &e))
}

/// Values of the `Etag` and `Last-Modified` headers.
///
/// (For reducing bandwidth used.)
#[derive(Debug, Eq, PartialEq)]
struct BandwidthHeaders {
    etag: HeaderValue,
    modified: HeaderValue,
}

/// A bandwidth reduction action to take.
///
/// Depends on presence and values of request headers and the modification
/// time of the file resource requested.
#[derive(Debug, Eq, PartialEq)]
enum Bandwidth {
    /// Resource not modified since last retrieval (send 304).
    NotModified,
    /// Resource new or modified since last retrieval, send `ETag` and
    /// `Last-Modified` headers along with resource.
    Modified(BandwidthHeaders),
    /// Last-modified time undiscernable, just send the resource.
    Unknown,
}

impl Bandwidth {
    /**
    Determine whether the requested resource needs to be sent, and the values
    of the bandwidth-saving headers to send with it if so.
    */
    fn check(md: &Metadata, req: &Request<Body>) -> Bandwidth {
        log::trace!("Bandwidth::check( [ Metadata ], {:?} ) called.", req.uri());
        let (since_epoch, last_modified) = match md.modified() {
            Ok(systime) => match systime.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(dur) => (dur, systime),
                Err(e) => {
                    log::error!("Last modified time {:?} before epoch: {}", &systime, &e);
                    return Bandwidth::Unknown;
                }
            },
            Err(_) => {
                return Bandwidth::Unknown;
            }
        };

        let etag = {
            let nanos = (since_epoch.subsec_nanos() as u64) << 32;
            let n = since_epoch.as_secs() | nanos;
            let mut bytes = SmallVec::<[u8; 20]>::new();
            if let Err(e) = write!(&mut bytes, "\"{:x}\"", n) {
                log::error!("Error formatting Etag {:x}: {}", n, &e);
                return Bandwidth::Unknown;
            }
            match HeaderValue::try_from(bytes.as_slice()) {
                Ok(val) => val,
                Err(e) => {
                    log::error!("Error headerizing Etag value {:?}: {}", &bytes, &e);
                    return Bandwidth::Unknown;
                }
            }
        };

        if let Some(val) = req.headers().get(header::IF_NONE_MATCH) {
            if val == etag {
                return Bandwidth::NotModified;
            }
        }

        let last_modified = OffsetDateTime::from(last_modified);

        if let Some(val) = req.headers().get(header::IF_MODIFIED_SINCE) {
            if let Ok(val) = val.to_str() {
                if let Ok(last) = OffsetDateTime::parse(val, &Rfc2822) {
                    if last_modified <= last {
                        return Bandwidth::NotModified;
                    }
                }
            }
        }

        let modified = {
            let mut bytes = SmallVec::<[u8; 36]>::new();
            if let Err(e) = last_modified.format_into(&mut bytes, &Rfc2822) {
                log::error!(
                    "Error formatting last modified date {:?}: {}",
                    &last_modified,
                    &e
                );
                return Bandwidth::Unknown;
            }
            match HeaderValue::try_from(bytes.as_slice()) {
                Ok(val) => val,
                Err(e) => {
                    log::error!(
                        "Error headerizing last modified date {:?}: {}",
                        &last_modified,
                        &e
                    );
                    return Bandwidth::Unknown;
                }
            }
        };

        let bw_headers = BandwidthHeaders { etag, modified };
        Bandwidth::Modified(bw_headers)
    }
}

fn write_dir_metadata<W, N, C, E>(
    mut w: W,
    modified: Result<SystemTime, E>,
    utf8name: N,
    encoded_name: C,
) -> std::io::Result<()>
where
    W: Write,
    N: AsRef<str>,
    C: AsRef<str>,
{
    use time::error::Format;

    let name = utf8name.as_ref();
    let encd = encoded_name.as_ref();

    writeln!(w, "<tr>\n    <td></td>\n    <td>")?;
    if let Ok(systime) = modified {
        let odt = OffsetDateTime::from(systime);
        odt.format_into(&mut w, INDEX_TIME_FMT)
            .map_err(|e| match e {
                Format::StdIo(e) => e,
                _ => {
                    panic!("This formatting error shouldn't happen.");
                }
            })?;
    }
    writeln!(
        w,
        "</td>\n    <td><a href=\"{}/\">{}/</a></td>\n</tr>",
        encd, name
    )
}

fn write_file_metadata<W, N, C, E>(
    mut w: W,
    size: u64,
    modified: Result<SystemTime, E>,
    utf8name: N,
    encoded_name: C,
) -> std::io::Result<()>
where
    W: Write,
    N: AsRef<str>,
    C: AsRef<str>,
{
    use time::error::Format;

    let name = utf8name.as_ref();
    let encd = encoded_name.as_ref();

    writeln!(w, "<tr>\n    <td>{}</td>\n    <td>", size)?;
    if let Ok(systime) = modified {
        let odt = OffsetDateTime::from(systime);
        odt.format_into(&mut w, INDEX_TIME_FMT)
            .map_err(|e| match e {
                Format::StdIo(e) => e,
                _ => {
                    panic!("This formatting error shouldn't happen.");
                }
            })?;
    }
    writeln!(
        w,
        "</td>\n    <td><a href=\"{}\">{}</a></td>\n</tr>",
        encd, name
    )
}

fn write_metadata<W>(w: W, entry: DirEntry) -> std::io::Result<()>
where
    W: Write,
{
    let metadata = entry.metadata()?;
    let name = entry.file_name();
    let utf8name = String::from_utf8_lossy(name.as_bytes());
    let encoded_name = urlencoding::encode_binary(name.as_bytes());
    let ftype = metadata.file_type();

    if ftype.is_file() {
        write_file_metadata(
            w,
            metadata.len(),
            metadata.modified(),
            utf8name,
            encoded_name,
        )?;
    } else if ftype.is_dir() {
        write_dir_metadata(w, metadata.modified(), utf8name, encoded_name)?;
    }
    // If it's anything else, don't write about it.

    Ok(())
}

fn write_index(uri_path: &str, p: &Path) -> Result<Vec<u8>, std::io::Error> {
    let mut v: Vec<u8> = Vec::new();
    v.write_all(INDEX_HEAD.as_bytes())?;
    v.write_all(uri_path.as_bytes())?;
    v.write_all(INDEX_MIDDLE.as_bytes())?;

    for res in std::fs::read_dir(p)? {
        write_metadata(&mut v, res?)?;
    }

    v.write_all(INDEX_FOOT.as_bytes())?;
    Ok(v)
}

pub fn respond_dir_index<P>(
    uri_path: &str,
    local_path: P,
    mut addl_headers: Vec<(HeaderName, HeaderValue)>,
) -> Result<Response<Body>, String>
where
    P: AsRef<Path>,
{
    let p = local_path.as_ref();
    log::trace!(
        "respond_dir_index( {}, [ {} add'l headers ] ) called.",
        p.display(),
        addl_headers.len()
    );

    let index_bytes =
        write_index(uri_path, p).map_err(|e| format!("Error writing response: {}", &e))?;
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
        .header(header::CONTENT_LENGTH, HeaderValue::from(index_bytes.len()))
        .body(Body::from(index_bytes))
        .map_err(|e| format!("Error building response: {}", &e))?;

    for (name, val) in addl_headers.drain(..) {
        resp.headers_mut().insert(name, val);
    }

    Ok(resp)
}

async fn make_body_stream<P>(p: P) -> Result<Body, std::io::Error>
where
    P: AsRef<Path>,
{
    let p = p.as_ref();
    log::trace!("make_body_stream( {:?} ) called.", p);

    let f = File::open(p).await?;
    let rs = ReaderStream::new(f);
    let bod = Body::wrap_stream(rs);
    Ok(bod)
}

pub async fn respond_static_file<P>(
    local_path: P,
    metadata: Metadata,
    req: Request<Body>,
) -> Result<Response<Body>, String>
where
    P: AsRef<Path>,
{
    let p = local_path.as_ref();
    log::trace!(
        "respond_static_file( {}, [ Metadata ] ) called.",
        p.display()
    );

    let bandwidth = Bandwidth::check(&metadata, &req);
    if Bandwidth::NotModified == bandwidth {
        return Ok(header_only(StatusCode::NOT_MODIFIED, vec![]));
    }

    let content_type = match p.extension() {
        Some(ext) => MIME_TYPES.mime_type(ext),
        None => &OCTET_STREAM,
    };

    let body = match make_body_stream(p).await {
        Ok(body) => body,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                return Ok(canned_html_response(StatusCode::NOT_FOUND));
            }
            ErrorKind::PermissionDenied => {
                return Ok(canned_html_response(StatusCode::FORBIDDEN));
            }
            _ => {
                return Err(format!("Error generating body: {}", &e));
            }
        },
    };

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, metadata.len());

    if let Bandwidth::Modified(bw) = bandwidth {
        resp = resp
            .header(header::ETAG, bw.etag)
            .header(header::LAST_MODIFIED, bw.modified);
    }

    resp.body(body)
        .map_err(|e| format!("Error generating Response: {}", &e))
}

async fn cgi_reparse_response<R>(r: R) -> Result<Response<Body>, String>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let mut reader = BufReader::new(r);
    let mut resp = Response::builder().status(StatusCode::OK);
    let mut buff = String::new();

    match reader.read_line(&mut buff).await {
        Ok(0) => {
            return Err("CGI script produced no output!".to_owned());
        }
        Err(e) => {
            return Err(format!("Error reading from output: {}", &e));
        }
        Ok(_) => { /* This is what we want to happen. */ }
    }

    while buff.trim() != "" {
        match buff.split_once(':') {
            Some((name, value)) => {
                resp = resp.header(name.trim(), value.trim());
            }
            None => {
                return Err(format!("Invalid header line: {:?}", &buff));
            }
        }

        buff.clear();
        match reader.read_line(&mut buff).await {
            Ok(0) => {
                // Ok(0) here indicates that the R generating the response
                // has produced only headers and no body. We're going to
                // consider this a reasonable outcome and not throw an error.
                break;
            }
            Err(e) => {
                return Err(format!("Error reading from output: {}", &e));
            }
            Ok(_) => { /* This is, again, the happy path. */ }
        }
    }

    let rs = ReaderStream::new(reader);
    let body = Body::wrap_stream(rs);
    resp.body(body)
        .map_err(|e| format!("Error generating CGI response: {}", &e))
}

async fn read_child_stderr<R>(mut r: R) -> Result<String, String>
where
    R: AsyncRead + Unpin,
{
    let mut stderr = String::new();
    if let Err(e) = r.read_to_string(&mut stderr).await {
        return Err(format!("Error reading child process stderr: {}", &e));
    }

    Ok(stderr)
}

pub async fn cgi<P>(
    p: P,
    mut req: Request<Body>,
    document_root: &Path,
) -> Result<Response<Body>, String>
where
    P: AsRef<Path>,
{
    let p = p.as_ref();
    log::trace!(
        "cgi( {}, [ Request ], {} ) called.",
        p.display(),
        document_root.display()
    );

    let mut cmd = Command::new(p);
    cmd.env_clear();
    cmd.env("DOCUMENT_ROOT", document_root);
    // HTTPS
    // TLS_VERSION
    // TLS_CIPHER
    match std::env::current_exe() {
        Ok(path) => {
            cmd.env("PATH", &path);
        }
        Err(e) => {
            log::error!("Error detecting current process path: {}", &e);
        }
    };
    if let Some(qstr) = req.uri().query() {
        cmd.env("QUERY_STRING", qstr);
    }

    if let Some::<&SocketAddr>(addr) = req.extensions().get() {
        let remote_ip = addr.ip().to_string();
        cmd.env("REMOTE_ADDR", &remote_ip);
        cmd.env("REMOTE_HOST", &remote_ip);
        cmd.env("REMOTE_PORT", addr.port().to_string());
    }
    cmd.env("REQUEST_METHOD", req.method().as_str());
    cmd.env("REQUEST_URI", req.uri().path());
    cmd.env("SCRIPT_FILENAME", p);
    cmd.env("SCRIPT_NAME", req.uri().path());
    cmd.env("SERVER_SOFTWARE", &*SERVER);
    // SERVER_NAME
    // SERVER_PORT
    for (name, value) in req.headers().iter() {
        let var_name: String = format!("HTTP_{}", name)
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    c.to_ascii_uppercase()
                } else if c == '-' {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        let var_val = OsStr::from_bytes(value.as_bytes());
        cmd.env(var_name, var_val);
    }

    let stdin_type = match req.method() {
        &Method::POST => Stdio::piped(),
        _ => Stdio::null(),
    };
    cmd.stdin(stdin_type);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("error spawning process: {}", &e))?;

    if let Some(handle) = child.stdin.take() {
        let mut child_input = BufWriter::new(handle);
        let output_reader = StreamReader::new(req.body_mut().map(|x| match x {
            Ok(chunk) => Ok(chunk),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{}", &e),
            )),
        }));
        let mut request_output = BufReader::new(output_reader);

        tokio::io::copy(&mut request_output, &mut child_input)
            .await
            .map_err(|e| format!("error writing request body to stdin: {}", &e))?;
    }

    let handle = child
        .stdout
        .take()
        .ok_or("Unable to get a handle on child process stdout.")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Unable to get a handle on child process stderr.")?;

    let (resp, exit_status, stderr) = tokio::try_join!(
        cgi_reparse_response(handle),
        child.wait().map(|x| match x {
            Ok(f) => Ok(f),
            Err(e) => Err(format!("{}", &e)),
        }),
        read_child_stderr(stderr),
    )?;

    if exit_status.success() {
        Ok(resp)
    } else {
        let estr = format!(
            "process returned unsuccessful exit status: {}\nStderr Output:\n{}",
            &exit_status, &stderr
        );
        Err(estr)
    }
}
