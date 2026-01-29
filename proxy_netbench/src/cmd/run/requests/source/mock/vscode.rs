use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::Uri,
};

use rand::{rng, seq::IndexedRandom as _};

use safechain_proxy_lib::{
    firewall::malware_list::{self, MALWARE_LIST_URI_STR_VSCODE},
    storage::SyncCompactDataStorage,
};

use crate::http::malware::download_malware_list_for_uri;

#[derive(Debug)]
pub(super) struct VSCodeUriGenerator {
    storage: Option<SyncCompactDataStorage>,
    malware_list: Vec<malware_list::ListDataEntry>,
}

impl VSCodeUriGenerator {
    pub(super) fn new(storage: SyncCompactDataStorage) -> Self {
        Self {
            storage: Some(storage),
            malware_list: Default::default(),
        }
    }

    pub(super) async fn random_uri(&mut self, malware_ratio: f64) -> Result<Uri, OpaqueError> {
        if let Some(storage) = self.storage.take() {
            self.malware_list = download_malware_list_for_uri(storage, MALWARE_LIST_URI_STR_VSCODE)
                .await
                .context("download vscode malware_list")?;
        }

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

        if rand::random_bool(malware_ratio) {
            let entry = self
                .malware_list
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
}
