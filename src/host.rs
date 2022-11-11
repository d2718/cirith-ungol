/*!
Individually configured hosts.
*/
use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    ops::Deref,
    path::PathBuf,
};

use hyper::{header, header::HeaderValue, Body, Method, Request, Response, StatusCode, Uri};

use crate::{
    resp,
    resp::{canned_html_response, cgi, header_only, respond_dir_index, respond_static_file},
};

/// Describes how to respond to requests for URI paths that map to
/// directories in the local filesystem.
#[derive(Debug)]
enum Index {
    /// Append the contained `PathBuf` to the URI and attempt to serve
    /// that file.
    Path(PathBuf),
    /// Append the contained `PathBuf` to the URI and attempt to serve
    /// that file if it exists, otherwise generate an automated HTML
    /// directory listing.
    Fallback(PathBuf),
    /// Generate an automated HTML directory listing.
    Auto,
    /// Respond with a 404.
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
            &name,
            &root,
            &index,
            autoindex,
            &cgi_dirs
        );

        let root = root
            .canonicalize()
            .map_err(|e| format!("Cannot canonicalize root directory {:?}: {}", &root, &e))?;

        let index_style = if let Some(index) = index {
            if !index.is_relative() {
                log::warn!(
                    "index is {:?}. For best results it should be a relative path like {:?}.",
                    &index,
                    "index.html"
                );
            }
            if autoindex {
                Index::Fallback(index)
            } else {
                Index::Path(index)
            }
        } else if autoindex {
            Index::Auto
        } else {
            Index::No
        };

        let mut cgi_opt: Option<BTreeSet<PathBuf>> = None;
        if !cgi_dirs.is_empty() {
            let mut cgi_set: BTreeSet<PathBuf> = BTreeSet::new();
            for p in &cgi_dirs {
                match p.canonicalize() {
                    Ok(cp) => {
                        cgi_set.insert(cp);
                    }
                    Err(e) => {
                        return Err(format!(
                            "cannot canonicalize CGI directory {:?}: {}",
                            &p, &e
                        ));
                    }
                }
            }
            cgi_opt = Some(cgi_set);
        }

        let h = Host {
            name,
            root,
            index: index_style,
            cgi_dirs: cgi_opt,
        };

        Ok(h)
    }

    fn to_local_path(&self, uri: &Uri) -> Option<PathBuf> {
        log::trace!("Host[{}]::to_local_path( {:?} ) called.", &self.name, uri);

        let decoded = match urlencoding::decode(uri.path()) {
            Ok(path_str) => path_str,
            Err(_) => {
                return None;
            }
        };
        let uri_path = PathBuf::from(decoded.deref());
        let uri_path = match uri_path.strip_prefix("/") {
            Ok(rel) => self.root.join(rel),
            Err(_) => self.root.join(uri_path),
        };
        match uri_path.canonicalize() {
            Ok(path) => Some(path),
            Err(_) => None,
        }
    }

    async fn handle(&self, req: Request<Body>) -> Response<Body> {
        log::trace!(
            "Host[{}]::handle( ... ) called. URI: {}",
            &self.name,
            req.uri()
        );

        let mut local_path = match self.to_local_path(req.uri()) {
            Some(pbuff) => pbuff,
            None => {
                return canned_html_response(StatusCode::NOT_FOUND);
            }
        };

        if let Some(cgi_dirs) = &self.cgi_dirs {
            if let Some(p) = local_path.parent() {
                if cgi_dirs.contains(p) {
                    match cgi(&local_path, req, &self.root).await {
                        Ok(response) => {
                            return response;
                        }
                        Err(e) => {
                            log::error!(
                                "Error running CGI program {}: {}",
                                &local_path.display(),
                                &e
                            );
                            return canned_html_response(StatusCode::INTERNAL_SERVER_ERROR);
                        }
                    }
                }
            }
        }

        if req.method() != Method::GET {
            return canned_html_response(StatusCode::METHOD_NOT_ALLOWED);
        }

        let mut metadata = match std::fs::metadata(&local_path) {
            Ok(md) => md,
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    return canned_html_response(StatusCode::NOT_FOUND);
                }
                ErrorKind::PermissionDenied => {
                    return canned_html_response(StatusCode::FORBIDDEN);
                }
                _ => {
                    return canned_html_response(StatusCode::INTERNAL_SERVER_ERROR);
                }
            },
        };

        if metadata.is_dir() {
            // Browsers won't deal with some relative URI paths properly if
            // the final character in the path of a directory isn't a '/'.
            let uri_path = req.uri().path();
            if uri_path.as_bytes().last() != Some(&b'/') {
                let mut new_path = String::from(uri_path);
                new_path.push('/');
                let new_path = match HeaderValue::try_from(new_path) {
                    Ok(val) => val,
                    Err(e) => {
                        log::error!("Error turning new path into HeaderValue: {}", &e);
                        return canned_html_response(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                };
                return header_only(
                    StatusCode::MOVED_PERMANENTLY,
                    vec![(header::LOCATION, new_path)],
                );
            }

            match &self.index {
                Index::Path(ref index_fname) => {
                    local_path = local_path.join(index_fname);
                    metadata = match std::fs::metadata(&local_path) {
                        Ok(md) => md,
                        _ => {
                            return canned_html_response(StatusCode::NOT_FOUND);
                        }
                    };
                }
                Index::Fallback(ref index_fname) => {
                    let maybe_index = local_path.join(index_fname);
                    metadata = match std::fs::metadata(&maybe_index) {
                        Ok(md) => {
                            local_path = maybe_index;
                            md
                        }
                        _ => match respond_dir_index(req.uri().path(), &local_path, vec![]) {
                            Ok(response) => {
                                return response;
                            }
                            Err(e) => {
                                log::error!(
                                    "Error serving directory index for {}: {}",
                                    local_path.display(),
                                    &e
                                );
                                return canned_html_response(StatusCode::INTERNAL_SERVER_ERROR);
                            }
                        },
                    }
                }
                Index::No => {
                    return canned_html_response(StatusCode::NOT_FOUND);
                }
                Index::Auto => match respond_dir_index(req.uri().path(), &local_path, vec![]) {
                    Ok(response) => {
                        return response;
                    }
                    Err(e) => {
                        log::error!(
                            "Error serving directory index for {}: {}",
                            local_path.display(),
                            &e
                        );
                        return canned_html_response(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                },
            }
        }

        match respond_static_file(&local_path, metadata, req).await {
            Ok(response) => response,
            Err(e) => {
                log::error!("Error serving static file {}: {}", local_path.display(), &e);

                canned_html_response(StatusCode::INTERNAL_SERVER_ERROR)
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
        log::trace!("HostConfig::from_hosts([ {} Hosts ]) called.", &hosts.len());

        let mut hc = HostConfig::empty();
        for host in hosts.drain(..) {
            hc.add(host)?;
        }

        Ok(hc)
    }

    pub fn default(self, default_hostname: &str) -> Result<HostConfig, String> {
        log::trace!(
            "HostConfig[{} Hosts]::default( {:?} ) called.",
            &self.hosts.len(),
            default_hostname
        );

        match self.default {
            Some(ref dh) => {
                return Err(format!("{:?} is already the default host.", &dh.name));
            }
            None => {
                let mut hosts = self.hosts;
                let new_default = hosts.remove(default_hostname);
                match new_default {
                    None => {
                        return Err(format!("There is no host {:?}.", new_default));
                    }
                    Some(nd) => {
                        let hc = HostConfig {
                            hosts,
                            default: Some(nd),
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
            &self.hosts.len(),
            &h.name
        );

        match self.hosts.insert(h.name.clone(), h) {
            None => Ok(()),
            Some(host) => {
                return Err(format!("Already a host {:?}; overwritten.", &host.name));
            }
        }
    }

    fn get_host<'a>(&'a self, hostname: &str) -> Option<&'a Host> {
        log::trace!(
            "HostConfig[{} hosts]::get_host( {:?} ) called.",
            &self.hosts.len(),
            hostname
        );

        match self.hosts.get(hostname) {
            Some(host) => Some(host),
            None => self.default.as_ref(),
        }
    }

    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        log::trace!(
            "HostConfig[{} Hosts]::handle( {} {} )",
            &self.hosts.len(),
            req.method(),
            req.uri()
        );

        if req.method() == Method::TRACE {
            match resp::trace(req) {
                Ok(response) => {
                    return response;
                }
                Err(e) => {
                    log::error!("Error generating TRACE response: {}", &e);
                    return canned_html_response(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }

        let hostname = match req.headers().get("host").map(HeaderValue::to_str) {
            Some(Ok(name)) => name,
            _ => "",
        };

        match self.get_host(hostname) {
            Some(h) => h.handle(req).await,
            None => canned_html_response(StatusCode::NOT_FOUND),
        }
    }
}
