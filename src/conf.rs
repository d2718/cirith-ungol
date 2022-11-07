/**! Configuration */

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use hyper::server::conn::AddrIncoming;
use serde::Deserialize;
use tls_listener::TlsListener;
use tokio_rustls::TlsAcceptor;

use crate::host::{Host, HostConfig};
use crate::tls;

const DEFAULT_REQUEST_LIMIT: usize = 24;
const DEFAULT_RATE_WINDOW: Duration = Duration::from_secs(4);
const DEFAULT_PRUNE_INTERVAL: usize = 1024;

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
    user: Option<String>,
    host: Vec<HostCfg>,
    default_host: Option<String>,
    blacklist: Option<Vec<IpAddr>>,
    http_port: Option<u16>,
    https_port: Option<u16>,
    no_http: Option<bool>,
    ssl_cert: Option<PathBuf>,
    ssl_key: Option<PathBuf>,
    rate_request_limit: Option<usize>,
    rate_window_ms: Option<u64>,
    rate_prune_interval: Option<usize>,
    no_rate_limit: Option<bool>,
}

pub struct Cfg {
    pub user: Option<String>,
    pub hosts: HostConfig,
    pub blacklist: Option<BTreeSet<IpAddr>>,
    pub port: Option<u16>,
    pub https_config: Option<(TlsListener<AddrIncoming, TlsAcceptor>, SocketAddr)>,
    pub rate_config: Option<(usize, Duration, usize)>,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            user: None,
            hosts: HostConfig::empty(),
            blacklist: None,
            port: Some(80),
            https_config: None,
            rate_config: None,
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

        let mut rate_request_limit = DEFAULT_REQUEST_LIMIT;
        let mut rate_window = DEFAULT_RATE_WINDOW;
        let mut rate_prune_interval = DEFAULT_PRUNE_INTERVAL;
        let mut no_rate_limit: bool = false;

        if let Some(b) = cf.no_rate_limit {
            no_rate_limit = b;
        }

        if let Some(x) = cf.rate_request_limit {
            if no_rate_limit {
                log::warn!("no_rate_limit set; ignoring rate_request_limit value of {}.", &x);
            } else {
                rate_request_limit = x;
            }
        }

        if let Some(x) = cf.rate_window_ms {
            if no_rate_limit {
                log::warn!("no_rate_limit set; ignoring rate_window_ms value of {}", &x);
            } else {
                rate_window = Duration::from_millis(x);
            }
        }

        if let Some(x) =  cf.rate_prune_interval {
            if no_rate_limit {
                log::warn!("no_rate_limit set; ignoring rate_prune interval value of {}", &x);
            } else {
                rate_prune_interval = x;
            }
        }

        if !no_rate_limit {
            cfg.rate_config = Some((
                rate_request_limit,
                rate_window,
                rate_prune_interval
            ));
        }

        Ok(cfg)
    }
}