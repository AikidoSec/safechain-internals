use std::collections::VecDeque;

use rama::{error::OpaqueError, http::Request, telemetry::tracing};
use rand::distr::{Distribution as _, weighted::WeightedIndex};
use safechain_proxy_lib::storage;

use crate::{
    config::{Product, ProductValues, default_product_values},
    mock::{
        MockRequestParameters, RequestMocker, pypi::PyPIMocker, random::RandomMocker,
        vscode::VSCodeMocker,
    },
};

/// Generate N random requests for a M iterations + warmup
pub async fn rand_requests(
    sync_storage: storage::SyncCompactDataStorage,
    iterations: usize,
    request_count: usize,
    request_count_warmup: usize,
    products: Option<ProductValues>,
    malware_ratio: f64,
) -> Result<(Vec<VecDeque<Request>>, VecDeque<Request>), OpaqueError> {
    let products = products.unwrap_or_else(default_product_values);
    tracing::info!(
        "using products: {}",
        products
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut random_mocker = RandomMocker::new();
    let mut vscode_mocker = VSCodeMocker::new(sync_storage.clone());
    let mut pypi_mocker = PyPIMocker::new(sync_storage);

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
                &mut random_mocker,
                &mut vscode_mocker,
                &mut pypi_mocker,
            )
            .await?,
        );
    }

    tracing::info!("generate #{request_count_warmup} random requests for warmup");
    let requests_warmup = rand_requests_inner(
        request_count_warmup,
        &products,
        malware_ratio,
        &mut random_mocker,
        &mut vscode_mocker,
        &mut pypi_mocker,
    )
    .await?;

    Ok((total_requests, requests_warmup))
}

/// Generate N random requests for a single iteration
async fn rand_requests_inner(
    request_count: usize,
    products: &ProductValues,
    malware_ratio: f64,
    random_mocker: &mut RandomMocker,
    vscode_mocker: &mut VSCodeMocker,
    pypi_mocker: &mut PyPIMocker,
) -> Result<VecDeque<Request>, OpaqueError> {
    let mut requests = VecDeque::with_capacity(request_count);

    let weights: Vec<_> = products.iter().map(|p| p.quality.as_u16()).collect();
    let dist = WeightedIndex::new(&weights).unwrap();
    for _ in 0..request_count {
        let product = products[dist.sample(&mut rand::rng())].value.clone();

        let params = MockRequestParameters { malware_ratio };

        let req = match product {
            Product::None | Product::Unknown(_) => random_mocker.mock_request(params).await?,
            Product::VSCode => vscode_mocker.mock_request(params).await?,
            Product::PyPI => pypi_mocker.mock_request(params).await?,
        };

        requests.push_back(req)
    }

    Ok(requests)
}
