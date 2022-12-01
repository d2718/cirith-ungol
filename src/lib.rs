pub mod bl;
pub mod conf;
pub mod host;
pub mod mime;
pub mod rate;
pub mod resp;
pub mod rlog;
pub mod tls;

use hyper::{
    Body, Response, StatusCode,
    header::{HeaderName, HeaderValue},
};
use once_cell::sync::Lazy;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub static SERVER: Lazy<String> = Lazy::new(|| format!("Cirith Ungol v{}", VERSION));

#[derive(Debug)]
pub struct CuErr {
    code: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    messages: Vec<String>,
}

impl CuErr {
    pub fn new<S: Into<String>>(message: S) -> CuErr {
        CuErr {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            headers: vec![],
            messages: vec![message.into()]
        }
    }

    pub fn with_code<C: Into<StatusCode>>(self, code: C) -> CuErr {
        CuErr {
            code: code.into(),
            headers: self.headers,
            messages: self.messages,
        }
    }

    pub fn with_header<N, V>(self, n: N, v: V) -> CuErr
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>
    {
        match (n.try_into(), v.try_into()) {
            (Ok(name), Ok(val)) => {
                let mut headers = self.headers;
                headers.push((name, val));
                CuErr {
                    code: self.code,
                    headers,
                    messages: self.messages,
                }
            },
            _ => {
                self.with_code(StatusCode::INTERNAL_SERVER_ERROR)
                    .wrap("Unable to add header value.")
            }
        }
    }

    pub fn wrap<S: Into<String>>(self, s: S) -> CuErr {
        let mut messages = self.messages;
        messages.push(s.into());
        CuErr {
            code: self.code,
            headers: self.headers,
            messages
        }
    }

    pub fn code(&self) -> StatusCode { self.code }

    pub fn to_response(self) -> http::response::Builder {
        let mut headers = self.headers;

        let mut b = Response::builder()
            .status(self.code);
        for (name, val) in headers.drain(..) {
            b = b.header(name, val);
        }

        b
    }

    pub fn has_messages(&self) -> bool { !self.messages.is_empty() }
}

impl From<String> for CuErr {
    fn from(s: String) -> CuErr { CuErr::new(s) }
}

impl From<&str> for CuErr {
    fn from(s: &str) -> CuErr { CuErr::new(String::from(s)) }
}

impl From<StatusCode> for CuErr {
    fn from(code: StatusCode) -> CuErr {
        CuErr {
            code,
            headers: vec![],
            messages: vec![],
        }
    }
}

impl std::fmt::Display for CuErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Returning error {}", &self.code)?;
        for (name, val) in self.headers.iter().rev() {
            writeln!(f, "    {}: {:?}", name, val)?;
        }
        for msg in self.messages.iter() {
            writeln!(f, "{}", msg)?;
        }
        Ok(())
    }
}

pub type Output = Result<Response<Body>, CuErr>;