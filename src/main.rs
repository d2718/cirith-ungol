use std::{
    error::Error,
    net::{SocketAddr, TcpListener},
    sync::Arc,
};

use axum::{
    Extension,
    middleware,
    Router,
    routing::get,
};
use simplelog::{ColorChoice, LevelFilter, TermLogger, TerminalMode};

use cirith_ungol::{
    cfg::Cfg,
    blacklist_layer, handler, log_request, utility_layer,
};

static DEFAULT_IP: [u8; 4] = [0, 0, 0, 0];

async fn wrapped_main() -> Result<(), Box<dyn Error>> {
    // TODO: Add `clap` and make this a command-line option.
    let mut cfg = Cfg::load("config.toml").await?;

    // TODO: Add a command-line option or environment variable to set
    // log level.
    let log_cfg = simplelog::ConfigBuilder::new()
        .add_filter_allow_str("cirith_ungol")
        .build();
    TermLogger::init(
        LevelFilter::Trace,
        log_cfg,
        TerminalMode::Stdout,
        ColorChoice::Auto,
    ).unwrap();

    log::info!("Configuration:\n{:#?}", &cfg);

    let tls_cfg = cfg.tls_cfg.take();
    let blacklist = cfg.blacklist.take();
    let cfg = Arc::new(cfg);

    let mut router = Router::new()
        .nest("/", get(handler).post(handler))
        .layer(middleware::from_fn(utility_layer))
        .layer(Extension(cfg.clone()))
        .layer(middleware::from_fn(log_request));

    if let Some(blacklist) = blacklist {
        log::debug!("blacklisting: {:?}", &blacklist);
        let blacklist = Arc::new(blacklist);
        router = router.layer(middleware::from_fn(blacklist_layer))
            .layer(Extension(blacklist.clone()));
    }
    
    match tls_cfg {
        Some(tls_cfg) => {
            let http_addr = SocketAddr::from((DEFAULT_IP, cfg.port));
            let https_addr = SocketAddr::from((DEFAULT_IP, tls_cfg.port));
            let http_listener = TcpListener::bind(&http_addr)?;
            let https_listener = TcpListener::bind(&https_addr)?;

            drop_root::set_user_group(&cfg.user, &cfg.user)?;

            tokio::try_join!(
                axum_server::from_tcp(http_listener).serve(
                    router.clone().into_make_service_with_connect_info::<SocketAddr>()
                ),
                axum_server::from_tcp_rustls(https_listener, tls_cfg.tls).serve(
                    router.into_make_service_with_connect_info::<SocketAddr>()
                )
            )?;
        },
        None => {
            let http_addr = SocketAddr::from((DEFAULT_IP, cfg.port));
            let http_listener = TcpListener::bind(&http_addr)?;
            axum_server::from_tcp(http_listener).serve(
                router.clone().into_make_service_with_connect_info::<SocketAddr>()
            ).await?;
        },
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = wrapped_main().await {
        println!("{}", &e);
        std::process::exit(1);
    }
}