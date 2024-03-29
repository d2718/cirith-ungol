use std::{
    convert::Infallible,
    error::Error,
    net::SocketAddr, sync::Arc
};

use futures_util::stream::StreamExt;
use hyper::{
    header,
    server::{accept, conn::AddrStream, Server},
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response,
};
use tokio_rustls::server::TlsStream;
use tower::{Service, ServiceBuilder};
use tower_http::{add_extension::AddExtensionLayer, set_header::response::SetResponseHeaderLayer};

use cirith_ungol::*;

async fn handle(req: Request<Body>) -> Result<Response<Body>, Box<dyn Error + Send + Sync>> {
    let hosts: &Arc<host::HostConfig> = req
        .extensions()
        .get()
        .expect("Host configuration not being injected into requests.");
    let hosts = hosts.clone();

    let meth = req.method().clone();
    match hosts.handle(req).await {
        Ok(response) => Ok(response),
        Err(e) => {
            if e.has_messages() {
                log::error!("{}", &e);
            }
            match meth {
                Method::GET | Method::POST => Ok(resp::html_body(e)),
                _ => Ok(resp::no_body(e)),
            }
        },
    }
}

fn init_logging(level: &str) {
    use simplelog::{ColorChoice, LevelFilter, TerminalMode};

    let level = level.to_ascii_lowercase();
    let level = match level.as_str() {
        "max" => LevelFilter::max(),
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    };

    let log_cfg = simplelog::ConfigBuilder::new()
        .set_time_format_rfc3339()
        .add_filter_allow_str("cirith_ungol")
        .build();

    #[cfg(debug_assertions)]
    let color_choice = ColorChoice::Auto;
    #[cfg(not(debug_assertions))]
    let color_choice = ColorChoice::Never;

    if simplelog::TermLogger::init(level, log_cfg, TerminalMode::Mixed, color_choice).is_err() {
        log::error!("Logging already started.");
    } else {
        log::info!("Logging started @level={:?}", &level);
        log::info!("{}", &*SERVER);
    }
}

/// Attempt to drop root privileges and become the given user.
fn drop_to_user(uname: Option<&str>) -> Result<(), String> {
    log::trace!("drop_to_user( {:?} ) called.", uname);

    if let Some(uname) = uname {
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            return Err(format!(
                "Root priviliges required to drop to user {:?}.",
                uname
            ));
        }
        drop_root::set_user_group(uname, uname)
            .map_err(|e| format!("Error dropping root privileges to user {:?}: {}", uname, &e))?;
        log::info!("Serving files as user {:?}", uname);
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn wrapped_main() -> Result<(), Box<dyn Error>> {
    let log_level = match std::env::var("CU_LOG") {
        Ok(lvl) => lvl.to_ascii_lowercase(),
        Err(_) => String::from("info"),
    };
    init_logging(&log_level);

    let args: Vec<String> = std::env::args().collect();
    let config_path: &str = args.get(1).map(String::as_str).unwrap_or("config.toml");
    let cfg = conf::Cfg::from_file(config_path)?;

    let bl_layer = match cfg.blacklist {
        Some(bl) => {
            bl::set(bl);
            Some(bl::BlacklistLayer::new())
        }
        None => None,
    };

    let limit_layer = match cfg.rate_config {
        Some((n_reqs, window, interval)) => {
            Some(rate::RateLimitLayer::new(n_reqs, window, interval)?)
        }
        None => None,
    };

    log::debug!("Host configuration:\n{:#?}", &cfg.hosts);

    log::debug!("CORS configuration:\n{:#?}", &cfg.cors_layer);

    let service = ServiceBuilder::new()
        .option_layer(bl_layer)
        .option_layer(limit_layer)
        .layer(rlog::RLogLayer::new())
        .layer(SetResponseHeaderLayer::if_not_present(
            header::SERVER,
            header::HeaderValue::from_str(&SERVER).unwrap(),
        ))
        .option_layer(cfg.cors_layer)
        .layer(AddExtensionLayer::new(Arc::new(cfg.hosts)))
        .service_fn(handle);

    let make_svc = make_service_fn(|stream: &AddrStream| {
        let remote_addr = stream.remote_addr();
        let mut inner_svc = service.clone();
        let outer_svc = service_fn(move |mut req: Request<Body>| {
            req.extensions_mut().insert(remote_addr);
            inner_svc.call(req)
        });

        async { Ok::<_, Infallible>(outer_svc) }
    });

    let tls_make_svc = make_service_fn(|stream: &TlsStream<AddrStream>| {
        let (io, _) = stream.get_ref();
        let remote_addr = io.remote_addr();
        let mut inner_svc = service.clone();
        let outer_svc = service_fn(move |mut req: Request<Body>| {
            req.extensions_mut().insert(remote_addr);
            inner_svc.call(req)
        });

        async { Ok::<_, Infallible>(outer_svc) }
    });

    match (cfg.port, cfg.https_config) {
        (Some(port), Some((listener, tls_addr))) => {
            log::info!("Serving HTTP on port {}", &port);
            log::info!("Serving HTTPS on port {}", &tls_addr.port());

            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            let listener = listener.filter(|conn| {
                if let Err(e) = conn {
                    log::error!("TLS connection error: {}", &e);
                    std::future::ready(false)
                } else {
                    std::future::ready(true)
                }
            });

            let http_server = Server::bind(&addr);
            let https_server = Server::builder(accept::from_stream(listener));
            drop_to_user(cfg.user.as_deref())?;

            tokio::try_join!(
                http_server.serve(make_svc),
                https_server.serve(tls_make_svc),
            )?;
        }
        (Some(port), None) => {
            log::info!("Serving HTTP on port {}", &port);

            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            let http_server = Server::bind(&addr);
            drop_to_user(cfg.user.as_deref())?;

            http_server.serve(make_svc).await?;
        }
        (None, Some((listener, tls_addr))) => {
            log::info!("Serving HTTPS on port {}", &tls_addr.port());

            let listener = listener.filter(|conn| {
                if let Err(e) = conn {
                    log::error!("TLS connection error: {}", &e);
                    std::future::ready(false)
                } else {
                    std::future::ready(true)
                }
            });
            let https_server = Server::builder(accept::from_stream(listener));
            drop_to_user(cfg.user.as_deref())?;

            https_server.serve(tls_make_svc).await?;
        }
        (None, None) => {
            return Err("This is pointless.".into());
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = wrapped_main() {
        eprintln!("{}", &e);
        std::process::exit(1);
    }
}
