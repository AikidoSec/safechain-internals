use std::{convert::Infallible, sync::Arc};

use rama::{
    Layer, Service,
    extensions::ExtensionsMut,
    io::{BridgeIo, Io},
    net::proxy::IoForwardService,
    telemetry::tracing,
};

use tokio::sync::Semaphore;

const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 2048;

pub fn default_max_concurrent_connections() -> usize {
    std::env::var("L4_PROXY_MAX_CONCURRENT_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONCURRENT_CONNECTIONS)
}

#[derive(Debug, Clone)]
pub struct ConcurrencyLimitLayer {
    semaphore: Arc<Semaphore>,
}

impl ConcurrencyLimitLayer {
    pub fn new(max_connections: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_connections)),
        }
    }
}

impl<S> Layer<S> for ConcurrencyLimitLayer {
    type Service = ConcurrencyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConcurrencyLimitService {
            inner,
            semaphore: self.semaphore.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ConcurrencyLimitService {
            inner,
            semaphore: self.semaphore,
        }
    }
}

#[derive(Debug)]
pub struct ConcurrencyLimitService<S> {
    inner: S,
    semaphore: Arc<Semaphore>,
}

impl<S: Clone> Clone for ConcurrencyLimitService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            semaphore: self.semaphore.clone(),
        }
    }
}

impl<S, Ingress, Egress> Service<BridgeIo<Ingress, Egress>> for ConcurrencyLimitService<S>
where
    S: Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible>,
    Ingress: Io + Unpin + ExtensionsMut,
    Egress: Io + Unpin + ExtensionsMut,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(
        &self,
        io: BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        match self.semaphore.try_acquire() {
            Ok(permit) => {
                let result = self.inner.serve(io).await;
                drop(permit);
                result
            }
            Err(_) => {
                tracing::debug!(
                    available = self.semaphore.available_permits(),
                    "L4 proxy concurrency limit reached, forwarding without inspection",
                );
                if let Err(err) = IoForwardService::new().serve(io).await {
                    tracing::debug!(error = %err, "passthrough forward error after concurrency limit");
                }
                Ok(())
            }
        }
    }
}
