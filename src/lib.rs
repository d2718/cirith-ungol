
pub mod cfg;
pub mod cgi;
pub mod mime;

use std::{
    collections::BTreeSet,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{
        header,
        method::Method,
        request::Request,
        status::StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    cfg::Cfg,
    cgi::RunResult,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn log_request<B>(req: Request<B>, next: Next<B>) -> Response {
    let request_info = {
        let method = req.method();
        let uri = req.uri();
        let version = req.version();

        let scheme = uri.scheme_str().unwrap_or("-schm");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("-auth");            // display
        let host = uri.host().unwrap_or("-host");   // &str
        let port = uri.port();
        let port_str = match &port {
            Some(p) => p.as_str(),
            None => "-p",
        };
        let path = uri.path();                      // &str
        let query = uri.query().unwrap_or("-q");    // &str
    
        let ci: &ConnectInfo<SocketAddr> = match req.extensions().get() {
            None => { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); },
            Some(ci) => ci,
        };

        format!(
            "{} {:?} {} {} {} {} {} {} {}",
            ci.0.ip(), version, method, scheme, authority,
            host, port_str, path, query
        )
    };

    let response = next.run(req).await;

    log::info!(
        "Req: {} {}",
        response.status().as_str(),
        &request_info
    );

    response
}

pub async fn blacklist_layer<B>(req: Request<B>, next: Next<B>) -> Response {
    let blacklist: &Arc<BTreeSet<IpAddr>> = req.extensions().get()
        .unwrap();

    let ci: &ConnectInfo<SocketAddr> = match req.extensions().get() {
        None => { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); },
        Some(ci) => ci,
    };

    let addr = ci.0.ip();

    if blacklist.contains(&addr) {
        log::info!(
            "BLACKLIST: {} {} {}",
            &addr,
            req.method(),
            req.uri()
        );
        return StatusCode::NOT_FOUND.into_response();
    }

    next.run(req).await
}

pub async fn utility_layer<B>(req: Request<B>, next: Next<B>) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        header::SERVER,
        header::HeaderValue::from_static(crate::cfg::server_string())
    );

    response
}

pub async fn handler(
    mut req: Request<Body>,
) -> Response {
    log::trace!("handler( [ req: uri: {:?} ] ) called.", &req.uri());

    let cfg = {
        let cfg: &Arc<Cfg> = req.extensions().get().unwrap();
        cfg.clone()
    };
    let ci: &ConnectInfo<SocketAddr> = match req.extensions().get() {
        None => { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); },
        Some(ci) => ci,
    };
    let addr = ci.0;

    let hostname = match req.uri().host() {
        Some(host) => host.as_bytes(),
        None => match req.headers().get(header::HOST) {
            Some(val) => val.as_bytes(),
            None => "".as_bytes(),
        }
    };

    log::debug!("hostname: {:?}", &hostname);

    let host = match cfg.hosts.get(hostname) {
        Some(host) => host,
        None => match &cfg.default_host {
            Some(hostname) => match cfg.hosts.get(hostname.as_bytes()) {
                Some(host) => host,
                None => { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); },
            },
            None =>  { return StatusCode::NOT_FOUND.into_response(); },
        }
    };

    let local_path = match host.resource_path(req.uri()) {
        Ok(path) => path,
        Err(e) => {
            log::error!("Error resolving local path for {:?}: {}", req.uri(), &e);
            return StatusCode::NOT_FOUND.into_response();
        },
    };

    log::debug!("local_path: {}\n({:?})", local_path.display(), &local_path);

    if !local_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(cgi_cfg) = &cfg.cgi {
        match cgi_cfg.try_run(&mut req, &local_path, &host, &addr).await {
            RunResult::Ok(response) => { return response; },
            RunResult::Err(e) => {
                log::error!(
                    "Error running {}: {}", local_path.display(), &e
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            },
            RunResult::Nope => { /* No CGI action; serve file normally. */ },
        }
    }

    // If a request has made it this far, we're just going to serve a static
    // file; GET is the only appropriate request method for that.
    if req.method() != Method::GET {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let mime_type = cfg.mime_type(&local_path);

    match tokio::fs::read(&local_path).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime_type)],
            bytes
        ).into_response(),
        Err(e) => match e.kind() {
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
            // For now this `ErrorKind` variant is an unstable feature.
            // ErrorKind::InvalidFilename => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }.into_response(),
    }
}