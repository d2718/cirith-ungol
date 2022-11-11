
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use hyper::{Body, header::HeaderValue, Request, Response};
use pin_project::pin_project;
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub struct RLogService<S> {
    inner: S,
}

impl<S> RLogService<S>
{
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[pin_project]
pub struct RLogFuture<F> {
    #[pin]
    response_future: F,
    data: String,
}

impl<F, E> Future for RLogFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.response_future.poll(cx) {
            Poll::Ready(result) => match result {
                Ok(resp) => {
                    //log::debug!("{:#?}", resp.headers());
                    log::info!("{} {}", resp.status().as_str(), &this.data);
                    Poll::Ready(Ok(resp))
                },
                Err(e) => {
                    log::info!("ERR {}", &this.data);
                    Poll::Ready(Err(e))
                },
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<ReqB, S> Service<Request<ReqB>> for RLogService<S>
where
    S: Service<Request<ReqB>, Response = Response<Body>>
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = RLogFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let addr: Option<&SocketAddr> = req.extensions().get();

        let host: &str = match req.headers().get("host")
            .map(HeaderValue::to_str)
        {
            Some(Ok(name)) => name,
            _ => "[-host]"
        };

        let data = match addr {
            Some(addr) => format!(
                "{} {} {} {}",
                host, addr, req.method(), req.uri()
            ),
            None => format!(
                "{} [-addr] {} {}",
                host, req.method(), req.uri()
            ),
        };
        let response_future = self.inner.call(req);

        RLogFuture { response_future, data }
    }

}

#[derive(Clone, Debug)]
pub struct RLogLayer {}
impl RLogLayer {
    pub fn new() -> Self { Self{} }
}

impl<S> Layer<S> for RLogLayer {
    type Service = RLogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RLogService::new(inner)
    }
}