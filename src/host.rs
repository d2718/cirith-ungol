/*!
Individually configured hosts.
*/
use std::{
    collections::{BTreeSet, BTreeMap},
    ffi::OsStr,
    io::ErrorKind,
    net::SocketAddr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use hyper::{body, Body,
    header,
    header::{HeaderName, HeaderValue},
    Method, Request, Uri, Response, StatusCode,
};
use time::{
    OffsetDateTime,
    format_description::well_known::Rfc2822,
};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
};

use crate::{
    MIME_TYPES,
    resp::{canned_html_response, header_only},
    SERVER,
};

const N_BLANK_HEADERS: usize = 64;

fn responsify(bytes: &[u8]) -> Result<Response<Body>, String> {
    use httparse::{EMPTY_HEADER, parse_headers, Status};

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
    let body = Body::from(Vec::from(&bytes[body_idx..]));

    let mut resp = Response::builder()
        .status(200)
        .body(body)
        .map_err(|e| format!(
            "Error generating response: {}", &e
        ))?;

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

    Ok(resp)
}

fn to_header_value(odt: OffsetDateTime) -> Option<HeaderValue> {
    log::trace!("to_header_value( {:?} ) called.", &odt);

    match odt.format(&Rfc2822) {
        Ok(tstamp) => {
            return match HeaderValue::try_from(tstamp) {
                Ok(hv) => Some(hv),
                Err(e) => {
                    log::error!("Error converting timestamp to HeaderValue: {}", &e);
                    None
                },
            };
        },
        Err(e) => {
            log::error!("Error formatting OffsetDateTime: {}", &e);
        },
    }

    None
}

#[derive(Debug)]
enum Index {
    Path(PathBuf),
    Auto,
    No,
}

#[derive(Debug)]
pub struct Host {
    name: String,
    root: PathBuf,
    index: Index,
    cgi_dirs: Option<BTreeSet<PathBuf>>,
}

impl Host {
    pub fn new(
        name: String,
        root: PathBuf,
        index: Option<PathBuf>,
        autoindex: bool,
        cgi_dirs: Vec<PathBuf>,
    ) -> Result<Host, String> {
        log::trace!(
            "Host::new( {:?}, {:?}, {:?}, {}, {:?} ) called.",
            &name, &root, &index, autoindex, &cgi_dirs
        );

        let root = root.canonicalize().map_err(|e| format!(
            "Cannot canonicalize root directory {:?}: {}", &root, &e
        ))?;
        let mut index_style = Index::No;
        if let Some(index) = index {
            if !index.is_relative() {
                log::warn!(
                    "index is {:?}. For best results it should be a relative path like {:?}.",
                    &index, "index.html"
                );
            }
            if autoindex {
                log::warn!(
                    "index value set ({:?}); autoindex value of true ignored.", &index
                );
            }
            index_style = Index::Path(index);
        } else if autoindex {
            return Err("Autoindexing not yet supported.".to_owned());
            //index_style = Index::Auto;
        }

        let mut cgi_opt: Option<BTreeSet<PathBuf>> = None;
        if !cgi_dirs.is_empty() {
            let mut cgi_set: BTreeSet<PathBuf> = BTreeSet::new();
            for p in &cgi_dirs {
                match p.canonicalize() {
                    Ok(cp) => { cgi_set.insert(cp); }
                    Err(e) => { return Err(format!(
                        "cannot canonicalize CGI directory {:?}: {}", &p, &e
                    )); },
                }
            }
            cgi_opt = Some(cgi_set);
        }

        let h = Host {
            name, root,
            index: index_style,
            cgi_dirs: cgi_opt
        };

        Ok(h)
    }

    fn to_local_path(&self, uri: &Uri) -> Result<PathBuf, String> {
        log::trace!(
            "Host[{}]::to_local_path( {:?} ) called.", &self.name, uri
        );

        let uri_path = PathBuf::from(uri.path());
        let mut uri_path = match uri_path.strip_prefix("/") {
            Ok(rel) => self.root.join(rel),
            Err(_) => self.root.join(uri_path),
        };
        if uri_path.is_dir() {
            if let Index::Path(ref index) = self.index {
                uri_path = uri_path.join(index);
            }
        }

        uri_path.canonicalize().map_err(|e| format!(
            "Canonicalization of {} failed: {}", uri_path.display(), &e
        ))
    }

    async fn cgi<P>(&self, p: P, mut req: Request<Body>) -> Response<Body>
    where P: AsRef<Path>
    {
        let p = p.as_ref();
        log::trace!(
            "Host[{}]::try_cgi( {} ) called.", &self.name, p.display()
        );

        let mut cmd = Command::new(p);
        cmd.env_clear();
        cmd.env("DOCUMENT_ROOT", &self.root);
        // HTTPS
        // TLS_VERSION
        // TLS_CIPHER
        match std::env::current_exe() {
            Ok(path) => {
                cmd.env("PATH", &path);
            },
            Err(e) => {
                log::error!(
                    "Error detecting current process path: {}", &e
                );
            },
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
                .chars().map(|c| {
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

        let stdin_type = match req.method() {
            &Method::POST => Stdio::piped(),
            _ => Stdio::null(),
        };
        cmd.stdin(stdin_type);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                log::error!(
                    "Error launching CGI process {}: {}", p.display(), &e
                );
                return canned_html_response(500);
            },
        };

        if let Some(mut handle) = child.stdin.take() {
            let bytes = match body::to_bytes(req.body_mut()).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!(
                        "Error reading request body: {}", &e
                    );
                    return canned_html_response(500);
                },
            };

            if let Err(e) = handle.write(&bytes).await {
                log::error!(
                    "Error writing request body to script {}: {}",
                    p.display(), &e
                );
                return canned_html_response(500);
            }
        }

        let output = match child.wait_with_output().await {
            Ok(output) => output,
            Err(e) => {
                log::error!(
                    "Error reading CGI process {} response: {}",
                    p.display(), &e
                );
                return canned_html_response(500);
            },
        };

        if output.status.success() {
            match responsify(&output.stdout) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("{}", &e);
                    canned_html_response(500)
                },
            }
        } else {
            log::error!(
                "Exit status: {} ({:?})\n{}",
                &output.status,
                output.status.code(),
                &String::from_utf8_lossy(&output.stderr)
            );
            canned_html_response(500)
        }
    }

    async fn handle(&self, req: Request<Body>) -> Response<Body> {
        log::trace!(
            "Host[{}]::handle( ... ) called. URI: {}",
            &self.name, req.uri()
        );

        let local_path = match self.to_local_path(req.uri()) {
            Ok(pbuff) => pbuff,
            Err(e) => {
                log::error!("{}", &e);
                return canned_html_response(404);
            },
        };

        let metadata = match std::fs::metadata(&local_path) {
            Ok(md) => md,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    return canned_html_response(404);
                },
                ErrorKind::PermissionDenied => {
                    return canned_html_response(403);
                },
                _ => {
                    return canned_html_response(500);
                },
            }
        };

        if let Some(cgi_dirs) = &self.cgi_dirs {
            if let Some(p) = local_path.parent() {
                if cgi_dirs.contains(p) {
                    return self.cgi(&local_path, req).await;
                }
            }
        }

        if req.method() != Method::GET {
            return canned_html_response(405);
        }

        let last_modified = match metadata.modified() {
            Ok(systime) => {
                let local_time = OffsetDateTime::from(systime);
                if let Some(hval) = req.headers().get(header::IF_MODIFIED_SINCE) {
                    if let Ok(hval_str) = hval.to_str() {
                        match OffsetDateTime::parse(hval_str, &Rfc2822) {
                            Ok(remote_time) => {
                                if local_time <= remote_time {
                                    return header_only(StatusCode::NOT_MODIFIED, vec![]);
                                }
                            },
                            Err(e) => {
                                log::error!(
                                    "Unable to parse header value time {:?}: {}",
                                    hval_str, &e
                                );
                            }
                        }
                    }
                }
                to_header_value(local_time)
            },
            _ => None,
        };

        let content_type = match local_path.extension() {
            Some(ext) => {
                let mime_type = MIME_TYPES.mime_type(ext);
                match HeaderValue::from_str(mime_type) {
                    Ok(hv) => hv,
                    Err(e) => {
                        log::warn!(
                            "Error turning MIME type {:?} into header value: {}",
                            mime_type, &e
                        );
                        HeaderValue::from_static("application/octet-stream")
                    },
                }
            }
            None => HeaderValue::from_static("application/octet-stream"),
        };

        match tokio::fs::read(&local_path).await {
            Ok(bytes) => {
                let content_length = bytes.len();
                let bod = Body::from(bytes);

                let mut resp = match Response::builder()
                    .status(200)
                    .header(
                        header::CONTENT_TYPE,
                        content_type
                    ).header(
                        header::CONTENT_LENGTH,
                        content_length
                    ).body(bod)
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        log::error!("Error generating response: {}", &e);
                        return canned_html_response(500);
                    },
                };

                if let Some(modded) = last_modified {
                    dbg!(&modded);
                    resp.headers_mut().insert(
                        header::LAST_MODIFIED,
                        modded
                    );
                }

                resp
            },
            Err(e) => match e.kind() {
                ErrorKind::NotFound => canned_html_response(404),
                ErrorKind::PermissionDenied => canned_html_response(403),
                _ => canned_html_response(500),
            }
        }
    }
}

#[derive(Debug)]
pub struct HostConfig {
    hosts: BTreeMap<String, Host>,
    default: Option<Host>,
}

impl HostConfig {
    pub fn empty() -> HostConfig {
        log::trace!("HostConfig::empty() called.");

        HostConfig {
            hosts: BTreeMap::new(),
            default: None,
        }
    }

    pub fn from_hosts(mut hosts: Vec<Host>) -> Result<HostConfig, String> {
        log::trace!(
            "HostConfig::from_hosts([ {} Hosts ]) called.", &hosts.len()
        );

        let mut hc = HostConfig::empty();
        for host in hosts.drain(..) {
            hc.add(host)?;
        }

        Ok(hc)
    }

    pub fn default(self, default_hostname: &str) -> Result<HostConfig, String> {
        log::trace!(
            "HostConfig[{} Hosts]::default( {:?} ) called.",
            &self.hosts.len(), default_hostname
        );

        match self.default {
            Some(ref dh) => { return Err(format!(
                "{:?} is already the default host.", &dh.name
            )); },
            None => {
                let mut hosts = self.hosts;
                let new_default = hosts.remove(default_hostname);
                match new_default {
                    None => { return Err(format!(
                        "There is no host {:?}.", new_default
                    )); },
                    Some(nd) => {
                        let hc = HostConfig {
                            hosts: hosts,
                            default: Some(nd)
                        };
                        Ok(hc)
                    }
                }
            }
        }
    }

    pub fn add(&mut self, h: Host) -> Result<(), String> {
        log::trace!(
            "HostConfig[{}] Hosts]::add( [ Host {:?} ] ) called.",
            &self.hosts.len(), &h.name
        );

        match self.hosts.insert(h.name.clone(), h) {
            None => Ok(()),
            Some(host) => { return Err(format!(
                "Already a host {:?}; overwritten.", &host.name
            )); },
        }
    }

    fn get_host<'a>(&'a self, hostname: &str) -> Option<&'a Host> {
        log::trace!(
            "HostConfig[{} hosts]::get_host( {:?} ) called.",
            &self.hosts.len(), hostname
        );

        match self.hosts.get(hostname) {
            Some(host) => Some(host),
            None => self.default.as_ref(),
        }
    }

    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        log::trace!(
            "HostConfig[{} Hosts]::handle( {} {} )",
            &self.hosts.len(), req.method(), req.uri()
        );
        dbg_log(req.uri());
        log::debug!(
            "Request Headers:\n{:#?}", req.headers()
        );

        let hostname = match req.headers().get("host").map(HeaderValue::to_str) {
            Some(Ok(name)) => name,
            _ => "",
        };

        match self.get_host(hostname) {
            Some(h) => h.handle(req).await,
            None => canned_html_response(404),
        }
    }
}

fn dbg_log(uri: &Uri) {
    log::debug!(
        "URI: {:?}
    schm: {:?}
    auth: {:?}
    host: {:?}
    path: {:?}
     qry: {:?}",
        uri,
        uri.scheme(),
        uri.authority(),
        uri.host(),
        uri.path(),
        uri.query(),
    );
}