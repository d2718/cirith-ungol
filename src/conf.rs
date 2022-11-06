/**! Configuration */

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use hyper::server::conn::AddrIncoming;
use serde::Deserialize;
use tls_listener::TlsListener;
use tokio_rustls::TlsAcceptor;

use crate::host::{Host, HostConfig};
use crate::tls;

#[derive(Debug, Deserialize)]
struct HostCfg {
    name: String,
    root: PathBuf,
    index: Option<PathBuf>,
    autoindex: Option<bool>,
    cgi: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct CfgFile {
    user: String,
    host: Vec<HostCfg>,
    default_host: Option<String>,
    blacklist: Option<Vec<IpAddr>>,
    http_port: Option<u16>,
    https_port: Option<u16>,
    no_http: Option<bool>,
    ssl_cert: Option<PathBuf>,
    ssl_key: Option<PathBuf>,
}

pub struct Cfg {
    pub user: String,
    pub hosts: HostConfig,
    pub blacklist: Option<BTreeSet<IpAddr>>,
    pub port: Option<u16>,
    pub https_config: Option<(TlsListener<AddrIncoming, TlsAcceptor>, SocketAddr)>,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            user: String::new(),
            hosts: HostConfig::empty(),
            blacklist: None,
            port: Some(80),
            https_config: None,
        }
    }
}

impl Cfg {
    pub fn from_file<P: AsRef<Path>>(p: P) -> Result<Cfg, String> {
        let p = p.as_ref();
        log::trace!(
            "Cfg::from_file( {} ) called.", p.display()
        );

        let cfg_bytes = std::fs::read(p).map_err(|e| format!(
            "Error reading config file {}: {}", p.display(), &e
        ))?;
        let mut cf: CfgFile = toml::from_slice(&cfg_bytes).map_err(|e| format!(
            "Error parsing config file {}: {}", p.display(), &e
        ))?;

        let mut cfg = Cfg::default();

        cfg.user = cf.user;
        
        if cf.host.is_empty() {
            return Err("You must configure at least one [[host]].".to_owned());
        }
        let mut hosts = Vec::with_capacity(cf.host.len());
        for hc in cf.host.drain(..) {
            let aidx = match hc.autoindex {
                Some(b) => b,
                None => false,
            };
            let h = Host::new(
                hc.name.clone(),
                hc.root,
                hc.index,
                aidx,
                hc.cgi
            ).map_err(|e| format!(
                "Error in [[host]] {:?}: {}", &hc.name, &e
            ))?;

            hosts.push(h);
        }
        {
            let mut hosts = HostConfig::from_hosts(hosts).map_err(|e| format!(
                "Error configuring hosts: {}", &e
            ))?;
            if let Some(hostname) = cf.default_host {
                hosts = hosts.default(&hostname).map_err(|e| format!(
                    "Error setting default host: {}", &e
                ))?;
            }
            cfg.hosts = hosts
        };

        if let Some(mut bl) = cf.blacklist {
            let blacklist: BTreeSet<IpAddr> = bl.drain(..).collect();
            cfg.blacklist = Some(blacklist);
        }

        match (cf.ssl_cert, cf.ssl_key) {
            (Some(cert_file), Some(key_file)) => {
                let port = cf.https_port.unwrap_or(443);
                let addr = SocketAddr::from(([0, 0, 0, 0], port));
                let listener = tls::make_listener(cert_file, key_file, &addr)?;
                cfg.https_config = Some((listener, addr));
            },
            (None, None) => {
                if let Some(port) = cf.https_port {
                    log::warn!("Ignoring https_port value of {} (no cert or key files specified).", port);
                }
            },
            _ => {
                return Err(
                    "ssl_cert value also requires an ssl_key value (and vice versa)."
                    .to_owned()
                );
            },
        }

        if cf.no_http == Some(false) {
            if cfg.https_config.is_none() {
                return Err(
                    "It's pointless to specify no_http=true without having HTTPS configured."
                    .to_owned()
                );
            }
            cfg.port = None;
        } else {
            cfg.port = Some(cf.http_port.unwrap_or(80));
        }

        Ok(cfg)
    }
}