use rama::{
    error::{ErrorContext, OpaqueError},
    net::{address::Domain, tls::server::SelfSignedData},
    telemetry::tracing,
    tls::boring::server::utils::self_signed_server_ca,
};

use super::PemKeyCrtPair;
use crate::storage::SyncSecrets;

const AIKIDO_SECRET_ROOT_CA: &str = "tls-root-ca";

pub(super) fn new_root_tls_crt_key_pair(
    secrets: &SyncSecrets,
) -> Result<PemKeyCrtPair, OpaqueError> {
    if let Some(pair) = secrets.load_secret_json(AIKIDO_SECRET_ROOT_CA)? {
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

    secrets
        .store_secret_json(AIKIDO_SECRET_ROOT_CA, &pair)
        .context("store self-generated CA pair")?;

    Ok(pair)
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    use rama::telemetry::tracing;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    #[ignore]
    fn test_new_root_tls_crt_key_pair_keyring() {
        let _ = new_root_tls_crt_key_pair(&SyncSecrets::new_keyring()).unwrap();
    }

    #[traced_test]
    #[test]
    fn test_new_root_tls_crt_key_pair_fs() {
        let dir = unique_empty_temp_dir("test_new_root_tls_crt_key_pair_fs").unwrap();
        let _ = new_root_tls_crt_key_pair(&SyncSecrets::new_fs(dir)).unwrap();
    }

    fn unique_empty_temp_dir(prefix: &str) -> std::io::Result<PathBuf> {
        let base = std::env::temp_dir();
        let pid = std::process::id();

        for attempt in 0..1000u32 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();

            let dir = base.join(format!("{prefix}_{pid}_{nanos}_{attempt}"));
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to create unique temp dir",
        ))
    }
}
