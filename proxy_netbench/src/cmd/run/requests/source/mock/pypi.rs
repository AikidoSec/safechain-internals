use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::Uri,
};

use rand::{rng, seq::IndexedRandom as _};

use safechain_proxy_lib::{
    firewall::malware_list::{self, MALWARE_LIST_URI_STR_PYPI},
    storage::SyncCompactDataStorage,
};

use crate::http::malware::download_malware_list_for_uri;

#[derive(Debug)]
pub(super) struct PyPIUriGenerator {
    storage: Option<SyncCompactDataStorage>,
    malware_list: Vec<malware_list::ListDataEntry>,
}

impl PyPIUriGenerator {
    pub(super) fn new(storage: SyncCompactDataStorage) -> Self {
        Self {
            storage: Some(storage),
            malware_list: Default::default(),
        }
    }

    pub(super) async fn random_uri(&mut self, malware_ratio: f64) -> Result<Uri, OpaqueError> {
        if let Some(storage) = self.storage.take() {
            self.malware_list = download_malware_list_for_uri(storage, MALWARE_LIST_URI_STR_PYPI)
                .await
                .context("download pypi malware_list")?;
        }

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
            .context("select random PyPI uri template")?;

        if rand::random_bool(malware_ratio) {
            let entry = self
                .malware_list
                .choose(&mut rng())
                .context("select random PyPI malware")?;
            template
                .replace("<PACKAGE_NAME>", &entry.package_name)
                .replace("<VERSION>", &entry.version.to_string())
                .parse()
                .context("parse PyPI uri")
        } else {
            template
                .replace("<PACKAGE_NAME>", "netbench-foo")
                .replace("<VERSION>", "bar")
                .parse()
                .context("parse PyPI uri")
        }
    }
}
