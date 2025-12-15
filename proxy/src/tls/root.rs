use rama::{
    error::{ErrorContext, OpaqueError},
    net::{address::Domain, tls::server::SelfSignedData},
    telemetry::tracing,
    tls::boring::server::utils::self_signed_server_ca,
};

use super::PemKeyCrtPair;

const AIKIDO_SECRET_SVC: &str = crate::utils::env::project_name();
const AIKIDO_SECRET_ROOT_CA: &str = "tls-root-ca";

pub(super) fn new_root_tls_crt_key_pair() -> Result<PemKeyCrtPair, OpaqueError> {
    if let Some(pair) = load_root_tls_crt_key_pair()? {
        tracing::debug!("return (secret) loaded CA crt key pair");
        return Ok(pair);
    }

    tracing::debug!("no CA crt key pair was present in secret storage, generate + store now...");

    let (crt, key) = self_signed_server_ca(&SelfSignedData {
        organisation_name: Some("Aikido Local Proxy".to_owned()),
        common_name: Some(Domain::from_static("aikido.dev")),
        subject_alternative_names: None,
    })
    .context("generate self signed TLS CA")?;

    let pair = PemKeyCrtPair {
        crt: String::from_utf8(crt.to_pem().context("generate PEM CA crt byte slice")?)
            .context("PEM CA crt byte slice as String")?
            .try_into()
            .context("PEM CA crt string as NonEmpty variant")?,
        key: String::from_utf8(
            key.private_key_to_pem_pkcs8()
                .context("generate PEM CA key byte slice")?,
        )
        .context("PEM CA key byte slice as String")?
        .try_into()
        .context("PEM CA key string as NonEmpty variant")?,
    };

    store_root_tls_crt_key_pair(&pair).context("store self-generated CA pair")?;

    Ok(pair)
}

fn store_root_tls_crt_key_pair(pair: &PemKeyCrtPair) -> Result<(), OpaqueError> {
    let v = serde_json::to_vec(pair).context("failed to (JSON) serialize PEM key-crt pair")?;

    keyring::Entry::new(AIKIDO_SECRET_ROOT_CA, AIKIDO_SECRET_SVC)
        .context("create Root ca entry")?
        .set_secret(&v)
        .context("store Root CA as secret")?;

    Ok(())
}

fn load_root_tls_crt_key_pair() -> Result<Option<PemKeyCrtPair>, OpaqueError> {
    match keyring::Entry::new(AIKIDO_SECRET_ROOT_CA, AIKIDO_SECRET_SVC)
        .context("create Root CA entry")
        .and_then(|entry| entry.get_secret().context("load Root CA entry secret"))
    {
        Ok(json_content) => Ok(Some(
            serde_json::from_slice(&json_content).context("json-decode ROOT CA pair info")?,
        )),
        Err(err) => {
            tracing::debug!("failed to read crt secret content: {err}; assume no root crt present");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rama::telemetry::tracing;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_new_root_tls_crt_key_pair() {
        let _ = new_root_tls_crt_key_pair().unwrap();
    }
}
