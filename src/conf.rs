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
use tower_http::cors::CorsLayer;

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
struct CorsConfig {
    allow_credentials: Option<bool>,
    allow_headers: Option<Vec<String>>,
    allow_methods: Option<Vec<String>>,
    allow_origins: Option<Vec<String>>,
    expose_headers: Option<Vec<String>>,
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
    cors_base: Option<String>,
    cors: Option<CorsConfig>,
}

/// Determines the base CORS settings, which can be further modified by
/// values in the `CorsConfig` struct.
#[derive(Debug)]
pub enum CorsBase {
    /// No CORS layer at all.
    None,
    /// All cross-origin requests are denied.
    Restrictive,
    /// All headers, methods, origins allowed, all headers exposed.
    Permissive,
    /// Credentials allowed, method, origin, headers mirrored.
    Very,
}

impl TryFrom<String> for CorsBase {
    type Error = String;

    fn try_from(s: String) -> Result<CorsBase, Self::Error> {
        let lc_s = s.to_ascii_lowercase();
        match lc_s.as_str() {
            "none" => Ok(CorsBase::None),
            "restrictive" => Ok(CorsBase::Restrictive),
            "permissive" => Ok(CorsBase::Permissive),
            "very" => Ok(CorsBase::Very),
            x => Err(format!(
                "\"{}\" not allowed (allowed values are \"none\", \"restrictive\", \"permissive\", \"very\")", x
            ))
        }
    }
}

impl From<CorsBase> for Option<CorsLayer> {
    fn from(base: CorsBase) -> Option<CorsLayer> {
        match base {
            CorsBase::None => None,
            CorsBase::Restrictive => Some(CorsLayer::new()),
            CorsBase::Permissive => Some(CorsLayer::permissive()),
            CorsBase::Very => Some(CorsLayer::very_permissive()),
        }
    }
}

/**
Generate the exact value to be passed to `ServiceBuilder::layer` to
(maybe) add the configured CORS layer.

Arguments are exactly the values of `CfgFile::cors_base` and
`CfgFile::cors`.
*/
fn make_cors_layer(
    base_string: Option<String>,
    config: Option<CorsConfig>
) -> Result<Option<CorsLayer>, String> {
    // These are all namespace collisions with `hyper` names that get used
    // all over the place, so we restrict them to just this function.
    use http::{
        header::{HeaderName, HeaderValue},
        method::Method,
    };

    log::trace!(
        "make_cors_layer( {:?}, {:?} ) called.", &base_string, &config
    );

    let base_type = match base_string {
        Some(s) => CorsBase::try_from(s).map_err(|e| format!(
            "Error in cors_base value: {}", &e
        ))?,
        None => CorsBase::Permissive,
    };

    let clayer: Option<CorsLayer> = base_type.into();
    let mut clayer = match clayer {
        Some(clayer) => clayer,
        None => {
            if config.is_some() {
                log::warn!("Values in [[cors]] stanza ignored because cors_base is set to \"none\".");
            }
            return Ok(None);
        },
    };

    let config = match config {
        None => { return Ok(Some(clayer)); },
        Some(config) => config,
    };

    if let Some(b) = config.allow_credentials {
        clayer = clayer.allow_credentials(b);
    }

    if let Some(mut v) = config.allow_headers {
        let mut heads: Vec<HeaderName> = Vec::with_capacity(v.len());
        for name in v.drain(..) {
            let head = HeaderName::try_from(name).map_err(|e| format!(
                "Error in allow_headers: {}", &e
            ))?;
            heads.push(head);
        }
        clayer = clayer.allow_headers(heads);
    }

    if let Some(v) = config.allow_methods {
        let mut methods: Vec<Method> = Vec::with_capacity(v.len());
        for mname in v.iter() {
            let m = Method::try_from(mname.as_str()).map_err(|e| format!(
                "Error in allow_methods value \"{}\": {}", mname, &e
            ))?;
            methods.push(m);
        }
        clayer = clayer.allow_methods(methods);
    }

    if let Some(mut v) = config.allow_origins {
        let mut origins: Vec<HeaderValue> = Vec::with_capacity(v.len());
        for oname in v.drain(..) {
            let oval = HeaderValue::try_from(oname).map_err(|e| format!(
                "Error in allow_origins: {}", &e
            ))?;
            origins.push(oval);
        }
        clayer = clayer.allow_origin(origins);
    }

    if let Some(mut v) = config.expose_headers {
        let mut heads: Vec<HeaderName> = Vec::with_capacity(v.len());
        for name in v.drain(..) {
            let head = HeaderName::try_from(name).map_err(|e| format!(
                "Error in expose_headers: {}", &e
            ))?;
            heads.push(head);
        }
        clayer = clayer.expose_headers(heads);
    }

    Ok(Some(clayer))
}

pub struct Cfg {
    pub user: Option<String>,
    pub hosts: HostConfig,
    pub blacklist: Option<BTreeSet<IpAddr>>,
    pub port: Option<u16>,
    pub https_config: Option<(TlsListener<AddrIncoming, TlsAcceptor>, SocketAddr)>,
    pub rate_config: Option<(usize, Duration, usize)>,
    pub cors_layer: Option<CorsLayer>,
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
            // ADD!
            cors_layer: None,
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

        cfg.cors_layer = make_cors_layer(cf.cors_base, cf.cors)?;

        Ok(cfg)
    }
}