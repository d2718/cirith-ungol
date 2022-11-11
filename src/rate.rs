use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use hyper::{Body, Request, Response, StatusCode};
use once_cell::sync::OnceCell;
use pin_project::pin_project;
use tower::{Layer, Service};

#[derive(Clone, Copy, Debug)]
struct LimitCounter {
    pub oldest: Instant,
    pub count: usize,
}

impl LimitCounter {
    pub fn new() -> LimitCounter {
        LimitCounter {
            oldest: Instant::now(),
            count: 1,
        }
    }

    pub fn should_serve_this_request(&mut self, limit: usize, cooldown: Duration) -> bool {
        if self.oldest.elapsed() > cooldown {
            self.count = 1;
            self.oldest = Instant::now();
            true
        } else if self.count < limit {
            self.count += 1;
            true
        } else {
            false
        }
    }

    pub fn is_expired(&self, cooldown: Duration) -> bool {
        self.oldest.elapsed() > cooldown
    }
}

struct Limiter {
    requests: HashMap<IpAddr, LimitCounter>,
    cooldown: Duration,
    limit: usize,
    prune_period: usize,
    request_counter: usize,
}

impl Limiter {
    fn new(limit: usize, cooldown: Duration, prune_period: usize) -> Limiter {
        Limiter {
            requests: HashMap::new(),
            limit,
            cooldown,
            prune_period,
            request_counter: 0,
        }
    }

    fn should_serve_hit(&mut self, addr: &IpAddr) -> bool {
        self.request_counter += 1;
        if self.request_counter > self.prune_period {
            log::trace!(
                "Pruning request limiter tree. Old size: {}",
                self.requests.len()
            );
            self.requests
                .retain(|_, counter| !counter.is_expired(self.cooldown));
            log::trace!("New size: {}", self.requests.len());
            self.request_counter = 0;
        }
        if let Some(counter) = self.requests.get_mut(addr) {
            counter.should_serve_this_request(self.limit, self.cooldown)
        } else {
            self.requests.insert(*addr, LimitCounter::new());
            true
        }
    }
}

static LIMITER: OnceCell<Mutex<Limiter>> = OnceCell::new();

#[pin_project(project = RateFutProj)]
pub enum RateLimitFuture<F> {
    Ok(#[pin] F),
    Throttled,
    Ignored,
}

impl<F, E> Future for RateLimitFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this: RateFutProj<'_, F> = self.project();

        match this {
            RateFutProj::Ok(f) => {
                let f: Pin<&mut F> = f;
                f.poll(cx)
            }
            RateFutProj::Throttled => {
                let res = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Body::empty())
                    .unwrap();
                Poll::Ready(Ok(res))
            }
            RateFutProj::Ignored => {
                let res = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap();
                Poll::Ready(Ok(res))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct RateLimitService<S> {
    inner: S,
}

impl<ReqB, S> Service<Request<ReqB>> for RateLimitService<S>
where
    S: Service<Request<ReqB>, Response = Response<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let addr: Option<&SocketAddr> = req.extensions().get();

        if let Some(addr) = addr {
            let ipaddr = addr.ip();
            {
                if let Some(mtx) = LIMITER.get() {
                    let mut guard = mtx.lock().unwrap();
                    if guard.should_serve_hit(&ipaddr) {
                        RateLimitFuture::Ok(self.inner.call(req))
                    } else {
                        RateLimitFuture::Throttled
                    }
                } else {
                    // If the IP address hashmap hasn't been instantiated,
                    // just let stuff through.
                    RateLimitFuture::Ok(self.inner.call(req))
                }
            }
        } else {
            // Ignored for no IP address.
            RateLimitFuture::Ignored
        }
    }
}

#[derive(Clone, Debug)]
pub struct RateLimitLayer {}

impl RateLimitLayer {
    pub fn new(
        limit: usize,
        cooldown: Duration,
        prune_period: usize,
    ) -> Result<RateLimitLayer, &'static str> {
        let limiter = Limiter::new(limit, cooldown, prune_period);
        if LIMITER.set(Mutex::new(limiter)).is_err() {
            Err("Already instantiated a RateLimitLayer.")
        } else {
            Ok(RateLimitLayer {})
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> RateLimitService<S> {
        RateLimitService { inner }
    }
}
