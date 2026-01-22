use std::{
    collections::{HashMap, hash_map::Entry},
    sync::LazyLock,
    time::Duration,
};

use rama::{
    Layer as _, Service as _,
    error::{ErrorContext as _, OpaqueError},
    http::{
        Body, Request, Response, Uri,
        client::EasyHttpWebClient,
        headers::specifier::{Quality, QualityValue},
        layer::{
            decompression::DecompressionLayer,
            map_request_body::MapRequestBodyLayer,
            map_response_body::MapResponseBodyLayer,
            retry::{ManagedPolicy, RetryLayer},
            timeout::TimeoutLayer,
        },
    },
    layer::MapErrLayer,
    service::BoxService,
    utils::{
        backoff::ExponentialBackoff,
        collections::{NonEmptyVec, non_empty_vec},
        rng::HasherRng,
    },
};

use rand::{
    distr::{Distribution as _, weighted::WeightedIndex},
    rng,
    seq::IndexedRandom,
};
use safechain_proxy_lib::{firewall::malware_list, storage};
use tokio::sync::Mutex;

rama::utils::macros::enums::enum_builder! {
    /// Some of the products we support and which to support
    /// explicitly in the benchmarks
    @String
    pub enum Product {
        /// No product
        None => "none" | "-",
        /// Visual Studio Code
        VSCode => "vscode",
        /// Python Package Index
        PyPI => "pypi",
    }
}

/// Generate N random requests for the given product ratio
pub async fn rand_requests(
    sync_storage: &storage::SyncCompactDataStorage,
    request_count: usize,
    products: Option<ProductValues>,
) -> Result<Vec<Request>, OpaqueError> {
    let products = products.unwrap_or_else(default_product_values);

    let mut requests = Vec::with_capacity(request_count);

    let weights: Vec<_> = products.iter().map(|p| p.quality.as_u16()).collect();
    let dist = WeightedIndex::new(&weights).unwrap();
    for _ in 0..request_count {
        let product = products[dist.sample(&mut rand::rng())].value.clone();
        let uri = generate_random_uri(sync_storage, product).await?;

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = uri;
        requests.push(req);
    }

    Ok(requests)
}

pub fn parse_product_values(input: &str) -> Result<ProductValues, String> {
    let result: Result<Vec<QualityValue<Product>>, _> =
        input.split(",").map(|s| s.parse()).collect();
    match result {
        Ok(values) => NonEmptyVec::try_from(values).map_err(|err| err.to_string()),
        Err(err) => Err(err.to_string()),
    }
}

/// Ratio of product values to be used for generating tests
pub type ProductValues = NonEmptyVec<QualityValue<Product>>;

/// Default [`ProductValues`] used in case none are defined in cli args.
fn default_product_values() -> ProductValues {
    non_empty_vec![
        QualityValue::new(Product::None, Quality::one()),
        QualityValue::new(Product::VSCode, Quality::new_clamped(100)),
        QualityValue::new(Product::PyPI, Quality::new_clamped(100)),
    ]
}

async fn generate_random_uri(
    sync_storage: &storage::SyncCompactDataStorage,
    product: Product,
) -> Result<Uri, OpaqueError> {
    static LISTS: LazyLock<Mutex<HashMap<Product, Vec<malware_list::ListDataEntry>>>> =
        LazyLock::new(Default::default);
    let mut lists = LISTS.lock().await;
    let list = lists.entry(product.clone());
    let entries = match list {
        Entry::Occupied(ref occupied_entry) => occupied_entry.get(),
        Entry::Vacant(vacant_entry) => {
            let fresh_entries = match product {
                Product::None | Product::Unknown(_) => vec![],
                Product::VSCode => {
                    download_malware_list_for_uri(
                        sync_storage.clone(),
                        "https://malware-list.aikido.dev/malware_vscode.json",
                    )
                    .await?
                }
                Product::PyPI => {
                    download_malware_list_for_uri(
                        sync_storage.clone(),
                        "https://malware-list.aikido.dev/malware_pypi.json",
                    )
                    .await?
                }
            };
            vacant_entry.insert(fresh_entries)
        }
    };

    match product {
        Product::None | Product::Unknown(_) => Ok(Uri::from_static(
            [
                "http://example.com",
                "https://example.com",
                "https://aikido.dev",
                "https://malware-list.aikido.dev/malware_pypi.json",
                "https://http-test.ramaproxy.org/method",
                "https://http-test.ramaproxy.org/response-stream",
                "https://http-test.ramaproxy.org/response-compression",
            ]
            .choose(&mut rng())
            .context("select random None uri")?,
        )),
        Product::VSCode => {
            const DOMAINS: &[&str] = &[
                "gallery.vsassets.io",
                "gallerycdn.vsassets.io",
                "marketplace.visualstudio.com",
                "netbench-foo.gallery.vsassets.io",
                "netbench-foo.gallerycdn.vsassets.io",
            ];
            const PATH_TEMPLATES: &[&str] = &[
                "/files/<publisher>/<extension>/<version>/foo",
                "/extensions/<publisher>/<extension>/foo",
                "/_apis/public/gallery/publishers/<publisher>/vsextensions/<extension>/foo",
                "/_apis/public/gallery/publisher/<publisher>/<extension>/foo",
                "/_apis/public/gallery/publisher/<publisher>/extension/<extension>/foo",
            ];

            let domain = DOMAINS
                .choose(&mut rng())
                .context("select random pypi domain")?;
            let path_template = PATH_TEMPLATES
                .choose(&mut rng())
                .context("select random pypi path template")?;

            // TODO: make this configurable via cli arg

            if rand::random_bool(0.1) {
                let entry = entries
                    .choose(&mut rng())
                    .context("select random pypi malware")?;
                let (publisher, extension) = entry
                    .package_name
                    .split_once(".")
                    .unwrap_or(("aikido", entry.package_name.as_str()));
                let path = path_template
                    .replace("<publisher>", publisher)
                    .replace("<extension>", extension)
                    .replace("<version>", &entry.version.to_string());
                format!("https://{domain}{path}")
                    .parse()
                    .context("parse pypi uri")
            } else {
                let path = path_template
                    .replace("<publisher>", "aikido")
                    .replace("<extension>", "netbench-foo")
                    .replace("<version>", "foo");
                format!("https://{domain}{path}")
                    .parse()
                    .context("parse pypi uri")
            }
        }
        Product::PyPI => {
            const URI_TEMPLATES: &[&str] = &[
                "https://pypi.org/pypi/<PACKAGE_NAME>/json",
                "https://pypi.org/simple/<PACKAGE_NAME>/",
                "https://files.pythonhosted.org/packages/abc/def/<PACKAGE_NAME>-<VERSION>-py3-none-any.whl",
                "https://files.pythonhosted.org/packages/source/d/<PACKAGE_NAME>/<PACKAGE_NAME>-<VERSION>.tar.gz",
                "https://pypi.org/pypi/<PACKAGE_NAME>/json",
                "https://pypi.org/",
                "https://pypi.org/help/",
            ];

            let template = URI_TEMPLATES
                .choose(&mut rng())
                .context("select random vscode uri template")?;

            if rand::random_bool(0.1) {
                let entry = entries
                    .choose(&mut rng())
                    .context("select random vscode malware")?;
                template
                    .replace("<PACKAGE_NAME>", &entry.package_name)
                    .replace("<VERSION>", &entry.version.to_string())
                    .parse()
                    .context("parse vscode uri")
            } else {
                template
                    .replace("<PACKAGE_NAME>", "netbench-foo")
                    .replace("<VERSION>", "bar")
                    .parse()
                    .context("parse vscode uri")
            }
        }
    }
}

async fn download_malware_list_for_uri(
    sync_storage: storage::SyncCompactDataStorage,
    uri: &'static str,
) -> Result<Vec<malware_list::ListDataEntry>, OpaqueError> {
    let client = shared_download_client();
    malware_list::RemoteMalwareList::download_data_entry_list(
        Uri::from_static(uri),
        sync_storage,
        client,
    )
    .await
}

fn shared_download_client() -> BoxService<Request, Response, OpaqueError> {
    static CLIENT: LazyLock<BoxService<Request, Response, OpaqueError>> = LazyLock::new(|| {
        let inner_https_client = EasyHttpWebClient::default();
        (
            MapResponseBodyLayer::new(Body::new),
            DecompressionLayer::new(),
            MapErrLayer::new(OpaqueError::from_std),
            TimeoutLayer::new(Duration::from_secs(60)),
            RetryLayer::new(
                ManagedPolicy::default().with_backoff(
                    ExponentialBackoff::new(
                        Duration::from_millis(100),
                        Duration::from_secs(30),
                        0.01,
                        HasherRng::default,
                    )
                    .expect("create exponential backoff impl"),
                ),
            ),
            MapRequestBodyLayer::new(Body::new),
        )
            .into_layer(inner_https_client)
            .boxed()
    });

    CLIENT.clone()
}
