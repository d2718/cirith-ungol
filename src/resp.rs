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
    io::{
        AsyncBufReadExt,
        AsyncRead,
        AsyncReadExt,
        AsyncSeekExt,
        BufReader,
        BufWriter,
    },
    process::Command,
};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::{
    mime::{MIME_TYPES, OCTET_STREAM},
    CuErr,
    Output,
    SERVER,
};

const MAX_BODY_SIZE: u64 = 1024 * 1024;

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

static OTHER_BODY: &str =
    "<h1>Error</h1>
    <p>There was an error attempting to fetch your resource.</p>";

pub fn canned_html_response<S>(
    code: S,
    mut addl_headers: Vec<(HeaderName, HeaderValue)>
) -> Response<Body>
where
    S: TryInto<StatusCode> + Debug + Copy,
{
    log::trace!(
        "canned_html_response( {:?}, [{} headers] ) called. Headers:\n{:#?}",
        &code, addl_headers.len(), &addl_headers
    );

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
                "resp::html_body(): unsupported status code {:?}, using 500.",
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

    let mut resp_builder = Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
        .header(header::CONTENT_LENGTH, HeaderValue::from(response_length));
    for (name, value) in addl_headers.drain(..) {
        resp_builder = resp_builder.header(name, value);
    }
    resp_builder.body(Body::from(v)).unwrap()
}

pub fn html_body(e: CuErr) -> Response<Body> {
    log::trace!("html_body( ... ) called. {:#?}", &e);

    let (title, contents) = match e.code() {
        StatusCode::FORBIDDEN => R_403,
        StatusCode::NOT_FOUND => R_404,
        StatusCode::METHOD_NOT_ALLOWED => R_405,
        StatusCode::PAYLOAD_TOO_LARGE => R_413,
        StatusCode::TOO_MANY_REQUESTS => R_429,
        StatusCode::INTERNAL_SERVER_ERROR => R_500,
        x => match x.canonical_reason() {
            Some(r) => (r, OTHER_BODY),
            None => ("Unspecified Error", OTHER_BODY),
        },
    };

    let response_length = CANNED_BASE_RESPONSE_LEN + title.len() + contents.len();
    let mut v: Vec<u8> = Vec::with_capacity(response_length);

    v.write_all(CANNED_HEAD.as_bytes()).unwrap();
    v.write_all(title.as_bytes()).unwrap();
    v.write_all(CANNED_MIDDLE.as_bytes()).unwrap();
    v.write_all(contents.as_bytes()).unwrap();
    v.write_all(CANNED_FOOT.as_bytes()).unwrap();

    e.to_response()
        .header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
        .header(header::CONTENT_LENGTH, HeaderValue::from(response_length))
        .body(Body::from(v)).unwrap()
}

pub fn no_body(e: CuErr) -> Response<Body> {
    log::trace!("no_body( ... ) called. {:#?}", &e);

    e.to_response().body(Body::empty()).unwrap()
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
                    log::error!("unheaderizable Etag value {:?}: {}", &bytes, &e);
                    return Bandwidth::Unknown;
                }
            }
        };

        if let Some(val) = req.headers().get(header::IF_NONE_MATCH) {
            if val == etag {
                return Bandwidth::NotModified;
            }
        }

        let if_range = req.headers().get(header::IF_RANGE);
        if let Some(val) = if_range {
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

        if let Some(val) = if_range {
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
    local_path: P,
    metadata: Metadata,
    req: Request<Body>,
) -> Output
where
    P: AsRef<Path>,
{
    let p = local_path.as_ref();
    log::trace!(
        "respond_dir_index( {}, [ Metadata ], [ Request {:?} ] ) called.",
        p.display(),
        req.method(),
    );

    let bandwidth = Bandwidth::check(&metadata, &req);
    if Bandwidth::NotModified == bandwidth {
        return Ok(header_only(StatusCode::NOT_MODIFIED, vec![]));
    }

    let index_bytes =
        write_index(req.uri().path(), p).map_err(|e| format!(
            "error generating index: {}", &e
        ))?;
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
        .header(header::CONTENT_LENGTH, HeaderValue::from(index_bytes.len()))
        .header(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
    
    if req.method() == &Method::HEAD {
        return Ok(header_only(StatusCode::OK, vec![]));
    }

    if let Bandwidth::Modified(bw) = bandwidth {
        resp = resp
            .header(header::ETAG, bw.etag)
            .header(header::LAST_MODIFIED, bw.modified);
    }

    resp.body(Body::from(index_bytes))
        .map_err(|e| CuErr::from(format!(
            "error building response: {}", &e
        )))
}

fn content_range_header(
    limits: Option<(u64, u64)>,
    metadata: &Metadata
) -> Result<HeaderValue, CuErr> {
    let filesize = metadata.len();
    log::trace!(
        "content_range_header( [ Metadata {} byte file ] ) called.",
        filesize
    );

    let text = match limits {
        Some((start, end)) => format!("bytes {}-{}/{}", start, end, filesize),
        None => format!("bytes */{}", filesize),
    };
    HeaderValue::try_from(text).map_err(|_| CuErr::from(format!(
        "unable to headerize Content-Range value for {} byte file",
        filesize
    )))
}

/**
If the request has a well-formed Range: header, return the offset and
length of the requested range.
*/
fn parse_range(req: &Request<Body>, metadata: &Metadata)
-> Result<Option<(u64, u64)>, CuErr> {
    let filesize = metadata.len();
    log::trace!(
        "parse_range( [ Request ], [ Metadata {} byte file ] )",
        filesize
    );


    let value_str = match req.headers().get(header::RANGE) {
        Some(val) => HeaderValue::to_str(val).map_err(|e| format!(
            "Range header unreadable: {}", &e
        ))?.trim(),
        None => { return Ok(None); }
    };

    let ranges_str = match value_str.split_once('=') {
        Some(("bytes", x)) => x.trim(),
        _ => {
            let cr_val = content_range_header(None, metadata)?;
            return Err(
                CuErr::from(StatusCode::RANGE_NOT_SATISFIABLE)
                    .with_header(header::CONTENT_RANGE, cr_val)
            );
        },
    };

    match ranges_str.split_once('-') {
        // Range: bytes 1234-
        Some((n, "")) => {
            let start_value: u64 = n.trim().parse()
                .map_err(|_| CuErr::from(StatusCode::BAD_REQUEST))?;

            if start_value >= filesize {
                let cr_val = content_range_header(None, metadata)?;
                return Err(
                    CuErr::from(StatusCode::RANGE_NOT_SATISFIABLE)
                        .with_header(header::CONTENT_RANGE, cr_val)
                );
            }

            let range_size = filesize - start_value;
            return Ok(Some((start_value, range_size)));
        },
        // Range: bytes -1234
        Some(("", n)) => {
            let suffix_size: u64 = n.trim().parse()
                .map_err(|_| CuErr::from(StatusCode::BAD_REQUEST))?;

            if suffix_size > filesize {
                let cr_val = content_range_header(None, metadata)?;
                return Err(
                    CuErr::from(StatusCode::RANGE_NOT_SATISFIABLE)
                        .with_header(header::CONTENT_RANGE, cr_val)
                );
            }

            let start_value = filesize - suffix_size;
            return Ok(Some((start_value, suffix_size)));
        },
        // Range: bytes 1234-5678
        Some((n, m)) => {
            /*
            If the client requests multiple ranges, we only want the first
            one (that's the only one we're going to serve). If there is more
            than one range specified in the header, they will be separated
            by commas. This takes everything up to the first comma in `m`
            (which should be the digits of the ending offset of the first
            range), or just the whole string `m` if there aren't any commas.
            */
            let m = m.split(',').next().unwrap_or(m);
            let (start_value, end_value) = match (
                n.parse::<u64>(), m.parse::<u64>()
            ) {
                (Ok(i), Ok(j)) => (i, j),
                _ => { return Err(CuErr::from(StatusCode::BAD_REQUEST)); },
            };

            if end_value >= start_value || end_value > filesize
            {
                let cr_val = content_range_header(None, metadata)?; 
                return Err(
                    CuErr::from(StatusCode::RANGE_NOT_SATISFIABLE)
                        .with_header(header::CONTENT_RANGE, cr_val)
                );
            }

            let range_size = end_value - start_value;
            return Ok(Some((start_value, range_size)));
        },

        _ => {
            return Err(CuErr::from(StatusCode::BAD_REQUEST));
        },
    }
}

async fn make_body_stream<P>(p: P) -> Result<Body, CuErr>
where
    P: AsRef<Path>,
{
    let p = p.as_ref();
    log::trace!("make_body_stream( {:?} ) called.", p);

    let f = File::open(p).await.map_err(|e| match e.kind() {
        ErrorKind::NotFound => CuErr::from(StatusCode::NOT_FOUND),
        ErrorKind::PermissionDenied => CuErr::from(StatusCode::FORBIDDEN),
        _ => CuErr::from(format!("error generating body stream: {}", &e)),
    })?;
    let rs = ReaderStream::new(f);
    let bod = Body::wrap_stream(rs);
    Ok(bod)
}

/**
This is here because it will eventually be used to respond to requests with
specified ranges.
*/
#[allow(dead_code)]
async fn make_chunk_stream<P>(
    p: P,
    start: u64,
    length: u64
) -> Result<Body, CuErr>
where P: AsRef<Path>,
{
    use std::io::SeekFrom;

    let p = p.as_ref();
    log::trace!("make_chunk_stream( {:?}, {}, {} ) called.", p, start, length);

    /*
    Error propagation from inside a BLOCK would be great if it were possible,
    but it's not. So I make this next block into a closure, then immediately
    call it and propagate _that_ error.

    I have no idea about the performance implications of this.
    */
    let f = || async {
        let mut f = File::open(p).await?;
        f.seek(SeekFrom::Start(start)).await?;
        Ok(f)
    };
    let f = f().await.map_err(|e: std::io::Error| match e.kind() {
        ErrorKind::NotFound => CuErr::from(StatusCode::NOT_FOUND),
        ErrorKind::PermissionDenied => CuErr::from(StatusCode::FORBIDDEN),
        _ => CuErr::from(format!("error generating body stream: {}", &e)),
    })?;

    let rs = ReaderStream::new(f.take(length));
    let bod = Body::wrap_stream(rs);
    Ok(bod)
}

pub async fn respond_static_file<P>(
    local_path: P,
    metadata: Metadata,
    req: Request<Body>,
) -> Output
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

    let parts: Option<(u64, u64)> = match parse_range(&req, &metadata)? {
        Some((offset, length)) => {
            if length > MAX_BODY_SIZE {
                Some((offset, MAX_BODY_SIZE))
            } else {
                Some((offset, length))
            }
        }
        None => {
            if metadata.len() > MAX_BODY_SIZE {
                Some((0, MAX_BODY_SIZE))
            } else {
                None
            }
        }
    };

    let (resp, body) = match parts {
        None => {
            let body = make_body_stream(p).await?;

            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, metadata.len())
                .header(
                    header::ACCEPT_RANGES,
                    HeaderValue::from_static("bytes"),
                );
            
            if let Bandwidth::Modified(bw) = bandwidth {
                resp = resp
                    .header(header::ETAG, bw.etag)
                    .header(header::LAST_MODIFIED, bw.modified);
            }

            (resp, body)
        },
        
        Some((offset, length)) => {
            let body = make_chunk_stream(p, offset, length).await?;
            let cr_val = content_range_header(
                Some((offset, offset+length)), &metadata
            )?;

            let resp = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, length)
                .header(header::CONTENT_RANGE, cr_val)
                .header(
                    header::ACCEPT_RANGES,
                    HeaderValue::from_static("bytes"),
                );
            
            (resp, body)
        },
    };

    resp.body(body).map_err(|e| CuErr::from(format!(
        "error building response: {}", &e
    )))
}

async fn cgi_reparse_response<R>(r: R) -> Output
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let mut reader = BufReader::new(r);
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
    let mut buff = String::new();

    match reader.read_line(&mut buff).await {
        Ok(0) => {
            return Err(CuErr::from("subprocess produced no output."));
        }
        Err(e) => {
            return Err(CuErr::from(
                format!("error reading subprocess output: {}", &e
            )));
        }
        Ok(_) => { /* This is what we want to happen. */ }
    }

    while buff.trim() != "" {
        match buff.split_once(':') {
            Some((name, value)) => {
                resp = resp.header(name.trim(), value.trim());
            }
            None => {
                return Err(CuErr::from(format!(
                    "invalid header line: {:?}", &buff
                )));
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
                return Err(CuErr::from(format!(
                    "error reading subprocess output: {}", &e
                )));
            }
            Ok(_) => { /* This is, again, the happy path. */ }
        }
    }

    let rs = ReaderStream::new(reader);
    let body = Body::wrap_stream(rs);
    resp.body(body)
        .map_err(|e| CuErr::from(format!(
            "error building response: {}", &e
        )))
}

async fn read_child_stderr<R>(mut r: R) -> Result<String, CuErr>
where
    R: AsyncRead + Unpin,
{
    let mut stderr = String::new();
    if let Err(e) = r.read_to_string(&mut stderr).await {
        return Err(CuErr::from(format!("{}", &e)));
    }

    Ok(stderr)
}

pub async fn cgi<P>(
    p: P,
    mut req: Request<Body>,
    document_root: &Path,
) -> Output
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
        .ok_or("unable to get a handle on child process stdout")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("unable to get a handle on child process stderr")?;

    let (resp, exit_status, stderr) = tokio::try_join!(
        cgi_reparse_response(handle),
        child.wait().map(|x| match x {
            Ok(f) => Ok(f),
            Err(e) => Err(CuErr::from(format!("{}", &e))),
        }),
        read_child_stderr(stderr).map(|x| match x {
            Ok(stderr) => Ok(stderr),
            Err(e) => Err(e.wrap("error reading child process stderr")),
        })
    )?;

    if exit_status.success() {
        Ok(resp)
    } else {
        let estr = format!(
            "process returned unsuccessful exit status: {}\nStderr Output:\n{}",
            &exit_status, &stderr
        );
        Err(CuErr::from(estr))
    }
}
