use rama::{
    error::OpaqueError,
    http::{Body, Request},
    telemetry::tracing,
};
use rand::distr::{Distribution as _, weighted::WeightedIndex};
use safechain_proxy_lib::storage;

use crate::config::{Product, ProductValues, default_product_values};

mod none;
mod pypi;
mod vscode;

pub mod malware;

/// Generate N random requests for a M iterations + warmup
pub async fn rand_requests(
    sync_storage: storage::SyncCompactDataStorage,
    iterations: usize,
    request_count: usize,
    request_count_warmup: usize,
    products: Option<ProductValues>,
    malware_ratio: f64,
) -> Result<(Vec<Vec<Request>>, Vec<Request>), OpaqueError> {
    let products = products.unwrap_or_else(default_product_values);
    tracing::info!(
        "using products: {}",
        products
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut vscode = self::vscode::VSCodeUriGenerator::new(sync_storage.clone());
    let mut pypi = self::pypi::PyPIUriGenerator::new(sync_storage);

    let mut total_requests = Vec::with_capacity(iterations);
    for i in 1..=iterations {
        tracing::info!(
            "generate #{request_count} random requests for iteration {i} / {iterations}"
        );
        total_requests.push(
            rand_requests_inner(
                request_count,
                &products,
                malware_ratio,
                &mut vscode,
                &mut pypi,
            )
            .await?,
        );
    }

    tracing::info!("generate #{request_count_warmup} random requests for warmup");
    let requests_warmup = rand_requests_inner(
        request_count_warmup,
        &products,
        malware_ratio,
        &mut vscode,
        &mut pypi,
    )
    .await?;

    Ok((total_requests, requests_warmup))
}

/// Generate N random requests for a single iteration
async fn rand_requests_inner(
    request_count: usize,
    products: &ProductValues,
    malware_ratio: f64,
    vscode: &mut self::vscode::VSCodeUriGenerator,
    pypi: &mut self::pypi::PyPIUriGenerator,
) -> Result<Vec<Request>, OpaqueError> {
    let mut requests = Vec::with_capacity(request_count);

    let weights: Vec<_> = products.iter().map(|p| p.quality.as_u16()).collect();
    let dist = WeightedIndex::new(&weights).unwrap();
    for _ in 0..request_count {
        let product = products[dist.sample(&mut rand::rng())].value.clone();

        let uri = match product {
            Product::None | Product::Unknown(_) => self::none::random_uri()?,
            Product::VSCode => vscode.random_uri(malware_ratio).await?,
            Product::PyPI => pypi.random_uri(malware_ratio).await?,
        };

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = uri;
        requests.push(req);
    }

    Ok(requests)
}
