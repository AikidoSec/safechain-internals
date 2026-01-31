use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::{Body, Request, Uri},
};

use rand::{rng, seq::IndexedRandom as _};

use safechain_proxy_lib::{
    firewall::malware_list::{self, MALWARE_LIST_URI_STR_PYPI},
    storage::SyncCompactDataStorage,
};

use crate::{http::malware::download_malware_list_for_uri, mock::RequestMocker};

#[derive(Debug)]
pub struct PyPIMocker {
    storage: Option<SyncCompactDataStorage>,
    malware_list: Vec<malware_list::ListDataEntry>,
}

impl PyPIMocker {
    pub fn new(storage: SyncCompactDataStorage) -> Self {
        Self {
            storage: Some(storage),
            malware_list: Default::default(),
        }
    }

    async fn random_uri(&mut self, malware_ratio: f64) -> Result<Uri, OpaqueError> {
        if let Some(storage) = self.storage.take() {
            self.malware_list = download_malware_list_for_uri(storage, MALWARE_LIST_URI_STR_PYPI)
                .await
                .context("download pypi malware_list")?;
        }

        const TARGET_URI_TEMPLATE: &[&str] = &[
            "https://files.pythonhosted.org/packages/abc/def/<PACKAGE_NAME>-<VERSION>-py3-none-any.whl",
            "https://files.pythonhosted.org/packages/source/d/<PACKAGE_NAME>/<PACKAGE_NAME>-<VERSION>.tar.gz",
        ];

        if rand::random_bool(malware_ratio) {
            let template = TARGET_URI_TEMPLATE
                .choose(&mut rng())
                .context("select random PyPI uri template")?;

            let entry = self
                .malware_list
                .choose(&mut rng())
                .context("select random PyPI malware")?;

            let package_name = entry.package_name.clone();
            let normalised_package_name = if template.ends_with(".whl") {
                package_name.replace("-", "_")
            } else {
                package_name
            };

            template
                .replace("<PACKAGE_NAME>", &normalised_package_name)
                .replace("<VERSION>", &entry.version.to_string())
                .parse()
                .context("parse PyPI uri")
        } else {
            const META_URI_TEMPLATES: &[&str] = &[
                "https://pypi.org/pypi/<PACKAGE_NAME>/json",
                "https://pypi.org/simple/<PACKAGE_NAME>/",
                "https://pypi.org/pypi/<PACKAGE_NAME>/json",
                "https://pypi.org/",
                "https://pypi.org/help/",
            ];

            const TOTAL_URI_LEN: usize = META_URI_TEMPLATES.len() + TARGET_URI_TEMPLATE.len();

            let idx = rand::random_range(0..TOTAL_URI_LEN);
            let value = if idx < META_URI_TEMPLATES.len() {
                META_URI_TEMPLATES[idx]
            } else {
                TARGET_URI_TEMPLATE[idx - META_URI_TEMPLATES.len()]
            };

            value
                .replace("<PACKAGE_NAME>", "netbench-foo")
                .replace("<VERSION>", "bar")
                .parse()
                .context("parse PyPI uri")
        }
    }
}

impl RequestMocker for PyPIMocker {
    async fn mock_request(
        &mut self,
        params: super::MockRequestParameters,
    ) -> Result<Request, OpaqueError> {
        let uri = self.random_uri(params.malware_ratio).await?;

        let mut req = Request::new(Body::empty());
        *req.uri_mut() = uri;
        Ok(req)
    }
}
