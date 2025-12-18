use rama::{
    error::{ErrorContext, OpaqueError},
    net::{address::Domain, tls::server::SelfSignedData},
    telemetry::tracing,
    tls::boring::{
        core::{pkey::PKey, x509::X509},
        server::utils::self_signed_server_ca,
    },
};
use serde::{Deserialize, Serialize};

use super::PemKeyCrtPair;
use crate::storage::SyncSecrets;

#[derive(Serialize, Deserialize)]
/// Versioned so we can modify storage in backwards compatible manner.
enum PemKeyCrtPairStorage {
    V1 { crt: Vec<u8>, key: Vec<u8> },
}

impl TryFrom<PemKeyCrtPairStorage> for super::PemKeyCrtPair {
    type Error = OpaqueError;

    fn try_from(value: PemKeyCrtPairStorage) -> Result<Self, Self::Error> {
        let (crt, key) = match value {
            PemKeyCrtPairStorage::V1 { crt, key } => (
                X509::from_der(&crt).context("create x509 crt from DER")?,
                PKey::private_key_from_der(&key).context("parse private key from DER")?,
            ),
        };
        Ok(PemKeyCrtPair {
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
        })
    }
}

const AIKIDO_SECRET_ROOT_CA: &str = "tls-root-ca-pair";

// TOOD: change this:
// - on linux continue do the same
// - on macos/windows:
//   - cert/key in cert store
//   - fingerprint in secret

pub(super) fn new_root_tls_crt_key_pair(
    secrets: &SyncSecrets,
) -> Result<PemKeyCrtPair, OpaqueError> {
    if let Some(pair) = secrets.load_secret::<PemKeyCrtPairStorage>(AIKIDO_SECRET_ROOT_CA)? {
        tracing::debug!("try to return (secret) loaded CA crt key pair");
        return pair.try_into();
    }

    tracing::debug!("no CA crt key pair was present in secret storage, generate + store now...");

    let (crt, key) = self_signed_server_ca(&SelfSignedData {
        organisation_name: Some("Aikido Local Proxy".to_owned()),
        common_name: Some(Domain::from_static("aikido.dev")),
        subject_alternative_names: None,
    })
    .context("generate self signed TLS CA")?;

    let storage_pair = PemKeyCrtPairStorage::V1 {
        crt: crt.to_der().context("generate DER CA crt byte slice")?,
        key: key
            .private_key_to_der_pkcs8()
            .context("generate DER CA key byte slice")?,
    };

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
        .store_secret(AIKIDO_SECRET_ROOT_CA, &storage_pair)
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
    #[cfg(not(target_os = "windows"))]
    // TODO: windows (cred storage) has max limit of 2560 bytes for secrets...
    // later today I'll add a new implementation of storage/cert-storage which will fix this
    fn test_new_root_tls_crt_key_pair_keyring() {
        for _ in 0..2 {
            let _ = new_root_tls_crt_key_pair(&SyncSecrets::new_keyring()).unwrap();
        }
    }

    #[traced_test]
    #[test]
    fn test_new_root_tls_crt_key_pair_fs() {
        let dir = unique_empty_temp_dir("test_new_root_tls_crt_key_pair_fs").unwrap();
        let secrets = SyncSecrets::new_fs(dir);
        for _ in 0..2 {
            let _ = new_root_tls_crt_key_pair(&secrets).unwrap();
        }
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
