use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    net::SocketAddr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use axum::{
    body::Body,
    http::{
        header::{HeaderName, HeaderValue},
        method,
        Request,
    },
    response::{IntoResponse, Response},
};
use hyper::body;
use tokio::{
    io::AsyncWriteExt,
    process::Command,
};

use crate::cfg::Host;

const N_BLANK_HEADERS: usize = 64;


#[derive(Debug)]
pub enum RunResult {
    Ok(Response),
    Err(String),
    Nope,
}

#[derive(Debug)]
pub struct PathCfg {
    pub path: PathBuf,
    pub execute: bool,
    pub interpreters: BTreeMap<OsString, PathBuf>,
}

#[derive(Debug)]
pub struct CgiCfg(BTreeMap<PathBuf, PathCfg>);

impl CgiCfg {
    pub fn new() -> CgiCfg {
        CgiCfg(BTreeMap::new())
    }
}

impl From<Vec<PathCfg>> for CgiCfg {
    fn from(v: Vec<PathCfg>) -> CgiCfg {
        let mut v = v;
        let map: BTreeMap<PathBuf, PathCfg> = v.drain(..)
            .map(|pcfg| (pcfg.path.clone(), pcfg))
            .collect();
        CgiCfg(map)
    }
}

impl CgiCfg {
    pub async fn try_run(
        &self,
        req: &mut Request<Body>,
        p: &Path,
        host: &Host,
        addr: &SocketAddr
    ) -> RunResult {
        log::trace!(
            "CgiCfg::try_run( ... ) called. Data:\npath: {}\nhost:\n{:?}",
            p.display(), host
        );

        let parent = match p.parent() {
            Some(p) => p,
            None => { return RunResult::Nope; }
        };
        let path_cfg = match self.0.get(parent) {
            Some(pcfg) => pcfg,
            None => { return RunResult::Nope; }
        };

        let mut cmd = match p.extension() {
            Some(ext) => match path_cfg.interpreters.get(ext) {
                Some(exec) => {
                    let mut cmd = Command::new(exec);
                    cmd.arg(p);
                    cmd
                }
                None => match path_cfg.execute {
                    true => Command::new(p),
                    false => { return RunResult::Nope; },
                },
            },
            None => match path_cfg.execute {
                true => Command::new(p),
                false => { return RunResult::Nope; },
            },
        };

        let uri = req.uri();
        let method = req.method();

        let remote_ip = addr.ip().to_string();
        let remote_port = addr.port().to_string();

        cmd.env_clear();
        cmd.env("DOCUMENT_ROOT", &host.root);
        // HTTPS
        // TLS_VERSION
        // TLS_CIPHER
        // PATH
        if let Some(qstr) = uri.query() {
            cmd.env("QUERY_STRING", qstr);
        }
        cmd.env("REMOTE_ADDR", &remote_ip);
        cmd.env("REMOTE_HOST", &remote_ip);
        cmd.env("REMOTE_PORT", &remote_port);
        cmd.env("REQUEST_METHOD", method.as_str());
        cmd.env("REQUEST_URI", uri.path());
        cmd.env("SCRIPT_FILENAME", p);
        cmd.env("SCRIPT_NAME", uri.path());
        // SERVER_NAME
        // SERVER_PORT
        // SERVER_SOFTWARE
        for (name, value) in req.headers().iter() {
            let var_name: String = format!("http_{}", name)
                .chars()
                .map(|c| {
                    if c.is_ascii_alphabetic() {
                        c.to_ascii_uppercase()
                    } else if c == '-' {
                        '_'
                    } else {
                        c
                    }
                }).collect();
            
            let var_val = OsStr::from_bytes(value.as_bytes());
            cmd.env(var_name, var_val);
        }

        let stdin_type = match method {
            &method::Method::POST => Stdio::piped(),
            _ => Stdio::null(),
        };

        cmd.stdin(stdin_type);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => { return RunResult::Err(e.to_string()); },
        };

        if let Some(mut handle) = child.stdin.take() {
            let bytes = match body::to_bytes(req.body_mut()).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    return RunResult::Err(format!(
                        "Error collecting request body: {}", &e
                    ));
                },
            };

            if let Err(e) = handle.write(&bytes).await {
                return RunResult::Err(format!(
                    "Error writing to child stdin: {}", &e
                ));
            }
        }

        let output = match child.wait_with_output().await {
            Ok(output) => output,
            Err(e) => {
                return RunResult::Err(
                    format!("Error waiting on output: {}", &e)
                );
            },
        };

        if output.status.success() {
            match output2response(&output.stdout) {
                Ok(resp) => RunResult::Ok(resp),
                Err(e) => RunResult::Err(e),
            }
        } else {
            let estr = format!(
                "Exit status: {} ({:?})\n{}",
                &output.status,
                output.status.code(),
                &String::from_utf8_lossy(&output.stderr)
            );
            RunResult::Err(estr)
        }
    }
}

fn output2response<'a>(bytes: &[u8]) -> Result<Response, String> {
    use httparse::{
        EMPTY_HEADER,
        parse_headers,
        Status,
    };

    let resp = {
        let mut empties = [EMPTY_HEADER; N_BLANK_HEADERS];
        let (body_idx, headers) = match parse_headers(&bytes, &mut empties) {
            Ok(Status::Complete((n, hdz))) => (n, hdz),
            Ok(Status::Partial) => { return Err(
                "Could only partially parse CGI output headers.".to_string()
            ); },
            Err(e) => { return Err(format!(
                "Error parsing CGI output headers: {}", &e
            )); },
        };

        let body = Vec::from(&bytes[body_idx..]);

        let mut resp = body.into_response();

        for h in headers.iter() {
            let name = HeaderName::from_bytes(h.name.as_bytes())
                .map_err(|e| format!(
                    "Unable to convert {:?} into header name: {}",
                    h.name, &e
                ))?;
            let val = HeaderValue::from_bytes(&h.value)
                .map_err(|e| format!(
                    "Unable to convert {:?} into header value: {}",
                    &String::from_utf8_lossy(&h.value), &e
                ))?;

            resp.headers_mut().insert(name, val);
        }
        resp
    };

    Ok(resp)
}