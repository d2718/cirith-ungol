use std::{
    fmt::Debug,
    io::Write,
};

use hyper::{
    Body, header, Response, StatusCode,
    header::{HeaderName, HeaderValue},
};

static HEAD: &str = include_str!("response_files/head.html");
static MIDDLE: &str = include_str!("response_files/middle.html");
static FOOT: &str = include_str!("response_files/foot.html");

static BASE_RESPONSE_LEN: usize = HEAD.len() + MIDDLE.len() + FOOT.len();

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

    let response_length = BASE_RESPONSE_LEN + title.len() + contents.len();
    let mut v: Vec<u8> = Vec::with_capacity(response_length);

    v.write_all(HEAD.as_bytes()).unwrap();
    v.write_all(title.as_bytes()).unwrap();
    v.write_all(MIDDLE.as_bytes()).unwrap();
    v.write_all(contents.as_bytes()).unwrap();
    v.write_all(FOOT.as_bytes()).unwrap();

    Response::builder()
        .status(code)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        )
        .header(
            header::CONTENT_LENGTH,
            HeaderValue::try_from(format!("{}", response_length)).unwrap(),
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