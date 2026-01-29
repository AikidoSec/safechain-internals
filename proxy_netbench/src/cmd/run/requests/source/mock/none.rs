use rama::{
    error::{ErrorContext as _, OpaqueError},
    http::Uri,
};

use rand::{rng, seq::IndexedRandom as _};

use safechain_proxy_lib::firewall::malware_list::MALWARE_LIST_URI_STR_PYPI;

pub(super) fn random_uri() -> Result<Uri, OpaqueError> {
    Ok(Uri::from_static(
        [
            "http://example.com",
            "https://example.com",
            "https://aikido.dev",
            MALWARE_LIST_URI_STR_PYPI,
            "https://http-test.ramaproxy.org/method",
            "https://http-test.ramaproxy.org/response-stream",
            "https://http-test.ramaproxy.org/response-compression",
        ]
        .choose(&mut rng())
        .context("select random None uri")?,
    ))
}
