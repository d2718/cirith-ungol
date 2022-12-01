/*!
Individually configured hosts.
*/
use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    ops::Deref,
    path::{Path, PathBuf},
};

use hyper::{header, header::HeaderValue, Body, Method, Request, StatusCode, Uri};

use crate::{
    resp,
    resp::{cgi, header_only, respond_dir_index, respond_static_file},
    CuErr, Output,
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

    fn to_local_path(&self, uri: &Uri) -> Result<PathBuf, CuErr> {
        log::trace!("Host[{}]::to_local_path( {:?} ) called.", &self.name, uri);

        let decoded = urlencoding::decode(uri.path()).map_err(|_|
            CuErr::from(StatusCode::NOT_FOUND)
        )?;
        let uri_path = PathBuf::from(decoded.deref());
        let uri_path = match uri_path.strip_prefix("/") {
            Ok(rel) => self.root.join(rel),
            Err(_) => self.root.join(uri_path),
        };
        uri_path.canonicalize().map_err(|_|
            CuErr::from(StatusCode::NOT_FOUND)
        )
    }

    fn can_cgi(&self, local_path: &Path, method: &Method) -> Result<bool, CuErr> {
        if let (Some(cgi_dirs), Some(p)) = (&self.cgi_dirs, local_path.parent()) {
            if cgi_dirs.contains(p) {
                if !matches!(method, &Method::GET | &Method::POST) {
                    return Err(
                        CuErr::from(StatusCode::METHOD_NOT_ALLOWED)
                            .with_header(
                                header::ALLOW,
                                HeaderValue::from_static("GET, POST"),
                            )
                    );
                }
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn handle(&self, req: Request<Body>) -> Output {
        log::trace!(
            "Host[{}]::handle( ... ) called. URI: {}",
            &self.name,
            req.uri()
        );

        let mut local_path = self.to_local_path(req.uri())?;

        if self.can_cgi(&local_path, req.method())? {
            return cgi(&local_path, req, &self.root).await.map_err(|e|
                e.wrap(format!(
                    "error running CGI program {}", local_path.display()
                )));
        }

        if !matches!(req.method(), &Method::GET | &Method::HEAD) {
            return Err(
                CuErr::from(StatusCode::METHOD_NOT_ALLOWED)
                    .with_header(
                        header::ALLOW,
                        HeaderValue::from_static("GET, HEAD")
                    )
            );
        }

        let mut metadata = std::fs::metadata(&local_path).map_err(|e|
            match e.kind() {
                ErrorKind::NotFound => CuErr::from(StatusCode::NOT_FOUND),
                ErrorKind::PermissionDenied => CuErr::from(StatusCode::FORBIDDEN),
                _ => CuErr::new(format!(
                    "error retrieving metadata for {}: {}",
                    local_path.display(), &e
                )),
            }
        )?;

        if metadata.is_dir() {
            // Browsers won't deal with some relative URI paths properly if
            // the final character in the path of a directory isn't a '/'.
            let uri_path = req.uri().path();
            if uri_path.as_bytes().last() != Some(&b'/') {
                let mut new_path = String::from(uri_path);
                new_path.push('/');
                let new_path = HeaderValue::try_from(new_path).map_err(|e|
                    CuErr::new(format!(
                        "can't convert new path to HeaderValue: {}", &e

                    )))?;
                return Ok(
                    header_only(
                        StatusCode::MOVED_PERMANENTLY,
                        vec![(header::LOCATION, new_path)],
                    )
                );
            }

            match &self.index {
                Index::Path(ref index_fname) => {
                    local_path = local_path.join(index_fname);
                    metadata = std::fs::metadata(&local_path).map_err(|_|
                        CuErr::from(StatusCode::NOT_FOUND))?;
                },
                Index::Fallback(ref index_fname) => {
                    let maybe_index = local_path.join(index_fname);
                    metadata = match std::fs::metadata(&maybe_index) {
                        Ok(md) => {
                            local_path = maybe_index;
                            md
                        }
                        _ => {
                            return respond_dir_index(&local_path, metadata, req);
                        },
                    }
                }
                Index::No => {
                    return Err(CuErr::from(StatusCode::NOT_FOUND));
                }
                Index::Auto => {
                    return respond_dir_index(&local_path, metadata, req);
                },
            }
        }

        respond_static_file(&local_path, metadata, req).await.map_err(|e|
            CuErr::new(format!(
                "error serving static file {}: {}",
                local_path.display(), &e
            ))
        ) 
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

    fn get_host<'a>(&'a self, hostname: Option<&str>) -> Option<&'a Host> {
        log::trace!(
            "HostConfig[{} hosts]::get_host( {:?} ) called.",
            &self.hosts.len(),
            hostname
        );

        if let Some(hostname) = hostname {
            if let Some(host) = self.hosts.get(hostname) {
                return Some(host);
            }
        }
        
        self.default.as_ref()
    }

    pub async fn handle(&self, req: Request<Body>) -> Output {
        log::trace!(
            "HostConfig[{} Hosts]::handle( {} {} )",
            &self.hosts.len(),
            req.method(),
            req.uri()
        );

        if req.method() == Method::TRACE {
            return resp::trace(req).map_err(|e|
                CuErr::new(format!(
                    "error generating TRACE response: {}", &e
                )));
        }

        let hostname = match req.headers().get("host").map(HeaderValue::to_str) {
            Some(Ok(name)) => Some(name),
            Some(Err(e)) => {
                log::error!("Error getting Host: header from request: {}", &e);
                None
            },
            None => None,
        };

        match self.get_host(hostname) {
            Some(h) => h.handle(req).await,
            None => Err(CuErr::from(StatusCode::NOT_FOUND)),
        }
    }
}
