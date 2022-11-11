use std::{
    fmt::Debug,
    fs::DirEntry,
    io::Write,
    os::unix::ffi::OsStrExt,
    path::Path,
    time::SystemTime,
};

use hyper::{
    Body, header, Response, StatusCode,
    header::{HeaderName, HeaderValue},
};
use time::{
    format_description::FormatItem,
    macros::format_description,
    OffsetDateTime,
};
use tokio::io::{
    BufReader, AsyncBufReadExt,
};

static CANNED_HEAD:   &str = include_str!("response_files/canned_head.html");
static CANNED_MIDDLE: &str = include_str!("response_files/canned_middle.html");
static CANNED_FOOT:   &str = include_str!("response_files/canned_foot.html");
static CANNED_BASE_RESPONSE_LEN: usize = CANNED_HEAD.len() + CANNED_MIDDLE.len() + CANNED_FOOT.len();

static INDEX_HEAD:   &str = include_str!("response_files/autoindex_head.html");
static INDEX_MIDDLE: &str = include_str!("response_files/autoindex_middle.html");
static INDEX_FOOT:   &str = include_str!("response_files/autoindex_foot.html");
//static INDEX_BASE_RESPONSE_LEN: usize = INDEX_HEAD.len() + INDEX_MIDDLE.len() + INDEX_FOOT.len();

static BUFFER_SIZE: usize = 4096;

static INDEX_TIME_FMT: &[FormatItem] = format_description!(
    "[year]-[month]-[day] [hour]:[minute]:[second]"
);

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
    S: TryInto<StatusCode> + Debug + Copy
{
    log::trace!("canned_html_response( {:?} ) called.", &code);

    let mut code: StatusCode = match code.try_into() {
        Ok(code) => code,
        Err(_) => {
            log::error!("Unable to convert to StatusCode: {:?}", &code);
            StatusCode::INTERNAL_SERVER_ERROR
        },
    };

    let (title, contents) = match code {
        StatusCode::FORBIDDEN => R_403,
        StatusCode::NOT_FOUND => R_404,
        StatusCode::METHOD_NOT_ALLOWED => R_405,
        StatusCode::PAYLOAD_TOO_LARGE => R_413,
        StatusCode::TOO_MANY_REQUESTS => R_429,
        StatusCode::INTERNAL_SERVER_ERROR => R_500,
        x => {
            log::warn!("resp::canned_html_response(): unsupported status code {:?}, using 500.", &x);
            code = StatusCode::INTERNAL_SERVER_ERROR;
            R_500
        },
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
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        )
        .header(
            header::CONTENT_LENGTH,
            HeaderValue::from(response_length),
        )
        .body(Body::from(v)).unwrap()
}

pub fn header_only<S>(
    code: S,
    mut addl_headers: Vec<(HeaderName, HeaderValue)>
) -> Response<Body>
where
    S: TryInto<StatusCode> + Debug + Copy
{
    log::trace!(
        "header_only( {:?}, [ {} add'l headers ] ) called.",
        &code, addl_headers.len()
    );

    let code: StatusCode = match code.try_into() {
        Ok(code) => code,
        Err(_) => {
            log::error!("Unable to convert StatusCode: {:?}", &code);
            StatusCode::INTERNAL_SERVER_ERROR
        },
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



fn write_dir_metadata<W, N, C, E>(
    mut w: W,
    modified: Result<SystemTime, E>,
    utf8name: N,
    encoded_name: C
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
        odt.format_into(&mut w, INDEX_TIME_FMT).map_err(|e| match e {
            Format::StdIo(e) => e,
            _ => { panic!("This formatting error shouldn't happen."); },
        })?;
    }
    writeln!(
        w, "</td>\n    <td><a href=\"{}/\">{}/</a></td>\n</tr>",
        encd, name
    )
}

fn write_file_metadata<W, N, C, E>(
    mut w: W,
    size: u64,
    modified: Result<SystemTime, E>,
    utf8name: N,
    encoded_name: C
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
        odt.format_into(&mut w, INDEX_TIME_FMT).map_err(|e| match e {
            Format::StdIo(e) => e,
            _ => { panic!("This formatting error shouldn't happen."); },
        })?;
    }
    writeln!(
        w, "</td>\n    <td><a href=\"{}\">{}</a></td>\n</tr>",
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
        write_file_metadata(w,
            metadata.len(),
            metadata.modified(),
            utf8name,
            encoded_name
        )?;
    } else if ftype.is_dir() {
        write_dir_metadata(w,
            metadata.modified(),
            utf8name,
            encoded_name
        )?;
    }
    // If it's anything else, don't write about it.

    Ok(())
}

fn write_index(
    uri_path: &str,
    p: &Path
) -> Result<Vec<u8>, std::io::Error> {
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

pub fn index<P>(
    uri_path: &str,
    local_path: P,
    mut addl_headers: Vec<(HeaderName, HeaderValue)>,
) -> Response<Body>
where
    P: AsRef<Path>
{
    let p = local_path.as_ref();
    log::trace!(
        "index( {}, [ {} add'l headers ] ) called.",
        p.display(), addl_headers.len()
    );

    match write_index(uri_path, p) {
        Ok(v) => {
            let mut resp = match Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html"),
                )
                .header(
                    header::CONTENT_LENGTH,
                    HeaderValue::from(v.len())
                )
                .body(Body::from(v))
            {
                Ok(resp) => resp,
                Err(e) => {
                    log::error!(
                        "Error building response: {}", &e
                    );
                    return canned_html_response(StatusCode::INTERNAL_SERVER_ERROR);
                },
            };

            for (name, val) in addl_headers.drain(..) {
                resp.headers_mut().insert(name, val);
            }

            resp
        },
        Err(e) => {
            log::error!(
                "Error writing autoindex of {:?}: {}",
                p.display(), &e
            );
            canned_html_response(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}