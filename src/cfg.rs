use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    net::IpAddr,
    path::{Path, PathBuf},
    //str::FromStr,
    time::Duration,
};

use axum::http::{status::StatusCode, Uri};
use axum_server::tls_rustls::RustlsConfig;
use once_cell::sync::Lazy;
use serde::Deserialize;

use crate::cgi::{CgiCfg, PathCfg};

static INDEX: &str = "index.html";

static SERVER: Lazy<String> = Lazy::new(||
    format!("Cirith Ungol v{}", crate::VERSION)
);

pub fn server_string() -> &'static str { &SERVER }

#[derive(Deserialize)]
struct HostCfgFile {
    name: String,
    root: PathBuf,
    index: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Interpreter {
    ext: String,
    bin: PathBuf,
}

#[derive(Deserialize)]
struct CgiPathCfgFile {
    path: String,
    execute: Option<bool>,
    interpreters: Option<Vec<Interpreter>>,
}

impl From<CgiPathCfgFile> for PathCfg {
    fn from(cpcf: CgiPathCfgFile) -> PathCfg {
        let mut interpreters: BTreeMap<OsString, PathBuf> = BTreeMap::new();
        if let Some(mut cf_ints) = cpcf.interpreters {
            for int in cf_ints.drain(..) {
                interpreters.insert(OsString::from(int.ext), int.bin);
            }
        }
        let execute = cpcf.execute.unwrap_or(false);
        let path = PathBuf::from(cpcf.path);

        PathCfg { path, execute, interpreters }
    }
}

#[derive(Deserialize)]
struct CfgFile {
    user: String,
    host: Vec<HostCfgFile>,
    default_host: Option<String>,
    blacklist: Option<Vec<IpAddr>>,
    http_port: Option<u16>,
    https_port: Option<u16>,
    ssl_cert: Option<PathBuf>,
    ssl_key: Option<PathBuf>,
    blacklist_delay_millis: Option<u64>,
    cgi: Option<Vec<CgiPathCfgFile>>,
}

#[derive(Debug)]
pub struct TlsConfig {
    pub port: u16,
    pub tls: RustlsConfig,
}

#[derive(Debug)]
pub struct Host {
    pub name: String,
    pub root: PathBuf,
    pub index: PathBuf,
}

impl Host {
    pub fn resource_path(&self, uri: &Uri) -> Result<PathBuf, String> {
        log::trace!("HostConfig[{:?}]::resource_path( {:?} )", self, uri);
        let uri_path = PathBuf::from(uri.path());
        let mut uri_path = match uri_path.strip_prefix("/") {
            Ok(rel) => self.root.join(rel),
            Err(_) => self.root.join(uri_path),
        };

        if uri_path.is_dir() {
            uri_path = uri_path.join(&self.index);
        }

        uri_path.canonicalize().map_err(|e| format!(
            "Canonicalization of {} failed: {}", uri_path.display(), &e
        ))
    }
}

#[derive(Debug)]
pub struct Cfg {
    pub user: String,
    pub hosts: BTreeMap<Vec<u8>, Host>,
    pub default_host: Option<String>,
    pub blacklist: Option<BTreeSet<IpAddr>>,
    pub port: u16,
    pub tls_cfg: Option<TlsConfig>,
    pub mime_types: HashMap<OsString, String>,
    pub blacklist_delay: Duration,
    pub cgi: Option<CgiCfg>,
}

impl Cfg {
    pub async fn load<P: AsRef<Path>>(p: P) -> Result<Cfg, String> {
        let p = p.as_ref();
        let bytes = std::fs::read(p).map_err(|e| format!(
            "Unable to read file {}: {}", p.display(), &e
        ))?;
        let mut cfgf: CfgFile = toml::from_slice(&bytes).map_err(|e| format!(
            "Unable to deserialize file {}: {}", p.display(), &e
        ))?;

        if cfgf.host.len() < 1 {
            return Err("Must configure at least one host.".to_string());
        }

        let mut blacklist: Option<BTreeSet<IpAddr>> = None;
        log::debug!("{:?}", &cfgf.blacklist);
        if let Some(mut addrs) = cfgf.blacklist {
            let list: BTreeSet<IpAddr> = addrs.drain(..).collect();
            blacklist = Some(list);
        }
        let blacklist_delay = match cfgf.blacklist_delay_millis {
            Some(n) => Duration::from_millis(n),
            None => Duration::from_millis(1000),
        };

        let port = cfgf.http_port.unwrap_or(80);
        
        let tls_cfg: Option<TlsConfig> = match (cfgf.ssl_cert, cfgf.ssl_key) {
            (Some(certpath), Some(keypath)) => {
                let tls = RustlsConfig::from_pem_file(
                    certpath, keypath
                ).await.map_err(|e| format!(
                    "Unable to load TLS configuration: {}", &e
                ))?;
                let port = cfgf.https_port.unwrap_or(443);
                Some(TlsConfig { port, tls })
            },
            (None, None) => None,
            _ => { return Err(
                "Option \"ssl_cert\" requires option \"ssl_key\" and vice versa.".to_string()
            ); },
        };

        let mut hosts: BTreeMap<Vec<u8>, Host> = BTreeMap::new();
        for hc in cfgf.host.drain(..) {
            if hc.root.is_relative() {
                return Err(format!(
                    "Error in [[host]] root value {}: Path must be absolute.",
                    hc.root.display()
                ));
            }

            let index = match hc.index {
                Some(index) => index,
                None => PathBuf::from(INDEX),
            };

            if index.is_absolute() {
                log::warn!(
                    "[[host]] index value {} is absolute path. For typical results this should be a filename like {:?}",
                    index.display(), INDEX
                );
            }

            hosts.insert(
                hc.name.clone().into_bytes(),
                Host { name: hc.name, root: hc.root, index }
            );
        }

        if let Some(ref def_h) = cfgf.default_host {
            if hosts.get(def_h.as_bytes()).is_none() {
                return Err(format!(
                    "default_host value {:?} must be the name of a configured host.",
                    def_h
                ));
            }
        }

        let cgi = cfgf.cgi.map(|mut cgicfg| {
            let v: Vec<PathCfg> = cgicfg.drain(..)
                .map(|x| PathCfg::from(x))
                .collect();
            CgiCfg::from(v)
        });

        let cfg = Cfg {
            mime_types: crate::mime::minimal_mime_map(), 
            default_host: cfgf.default_host,
            user: cfgf.user,
            hosts, blacklist, blacklist_delay, port, tls_cfg, cgi,
        };
        Ok(cfg)
    }

/*     pub fn resource_path(&self, uri: &Uri) -> Result<PathBuf, StatusCode> {
        log::trace!("Cfg::resource_path( {:?} ) called.", &uri);

        let host = match uri.host() {
            Some(host) => host,
            None => match &self.default_host {
                Some(host) => host.as_str(),
                None => { return Err(StatusCode::BAD_REQUEST); }
            }
        };

        let hcfg = match self.hosts.get(host) {
            Some(hcfg) => hcfg,
            None => { return Err(StatusCode::NOT_FOUND); },
        };

        let mut p = match hcfg.resource_path(uri) {
            Ok(pbuff) => pbuff,
            Err(e) => {
                log::error!(
                    "Unable to canonicalize {:?}:{}: {}",
                    host, uri.path(), &e
                );
                return Err(StatusCode::NOT_FOUND);
            },
        };

        if p.is_dir() {
            p = p.join(&hcfg.index);
        }

        Ok(p)
    } */

    pub fn mime_type<'a, P: AsRef<Path>>(&'a self, p: P) -> &'a str {
        let p = p.as_ref();
        if let Some(ext) = p.extension() {
            if let Some(mtype) = self.mime_types.get(ext) {
                return mtype.as_str();
            }
        }

        return "application/octet-stream";
    }
}