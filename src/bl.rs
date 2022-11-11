use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use hyper::{Body, Request, Response, StatusCode};
use once_cell::sync::OnceCell;
use pin_project::pin_project;
use tower::{Layer, Service};

static BLACKLIST: OnceCell<BTreeSet<IpAddr>> = OnceCell::new();

pub fn set(blacklist: BTreeSet<IpAddr>) {
    let n_addrs = blacklist.len();
    match BLACKLIST.set(blacklist) {
        Ok(()) => {
            log::info!("Blacklisting {} addresses.", &n_addrs);
        }
        Err(_) => {
            log::error!("Attempt to initialize already-initialized Blacklist.");
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlacklistService<S> {
    inner: S,
}

#[pin_project(project = BlFutProj)]
pub enum BlacklistFuture<F> {
    Ok(#[pin] F),
    Blacklisted,
}

impl<F, E> Future for BlacklistFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this: BlFutProj<'_, F> = self.project();

        match this {
            BlFutProj::Ok(f) => {
                let f: Pin<&mut F> = f;
                f.poll(cx)
            }
            BlFutProj::Blacklisted => {
                let res = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap();
                Poll::Ready(Ok(res))
            }
        }
    }
}

impl<ReqB, S> Service<Request<ReqB>> for BlacklistService<S>
where
    S: Service<Request<ReqB>, Response = Response<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BlacklistFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let addr: Option<&SocketAddr> = req.extensions().get();

        match addr {
            Some(addr) => {
                if let Some(blacklist) = BLACKLIST.get() {
                    if blacklist.contains(&addr.ip()) {
                        log::info!("BLACKLISTED: {}", &addr.ip());
                        BlacklistFuture::Blacklisted
                    } else {
                        BlacklistFuture::Ok(self.inner.call(req))
                    }
                } else {
                    BlacklistFuture::Ok(self.inner.call(req))
                }
            }
            None => {
                log::info!("BLACKLISTED for no addr.");
                BlacklistFuture::Blacklisted
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlacklistLayer {}
impl BlacklistLayer {
    pub fn new() -> Self {
        Self {}
    }
}

impl<S> Layer<S> for BlacklistLayer {
    type Service = BlacklistService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BlacklistService { inner }
    }
}
