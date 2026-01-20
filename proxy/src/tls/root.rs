use rama::{
    error::{ErrorContext, OpaqueError},
    net::{address::Domain, tls::server::SelfSignedData},
    telemetry::tracing,
    tls::boring::{
        core::{hash::MessageDigest, pkey::PKey, x509::X509},
        server::utils::self_signed_server_ca,
    },
    utils::str::NonEmptyStr,
};

use serde::{Deserialize, Serialize};

use super::PemKeyCrtPair;
use crate::storage::{SyncCompactDataStorage, SyncSecrets};

#[derive(Serialize, Deserialize)]
enum DataProxyRootCAKey {
    V1 { key: Vec<u8>, fp: Vec<u8> },
}

impl DataProxyRootCAKey {
    fn key(&self) -> &[u8] {
        match self {
            DataProxyRootCAKey::V1 { key, .. } => key.as_slice(),
        }
    }

    fn crt_fingerprint(&self) -> &[u8] {
        match self {
            DataProxyRootCAKey::V1 { fp, .. } => fp.as_slice(),
        }
    }
}

#[derive(Serialize, Deserialize)]
enum DataProxyRootCACrt {
    V1 { crt: Vec<u8> },
}

impl DataProxyRootCACrt {
    fn try_crt_as_pem(&self, expected_fp: &[u8]) -> Result<NonEmptyStr, OpaqueError> {
        let crt_der = match self {
            DataProxyRootCACrt::V1 { crt } => crt.as_slice(),
        };

        let crt = X509::from_der(crt_der).context("create x509 crt from read DER")?;
        let crt_fp = crt
            .digest(MessageDigest::sha256())
            .context("(re)compute CA crt fingerprint (digest) for verification")?;

        if !crt_fp.eq(expected_fp) {
            return Err(OpaqueError::from_display(format!(
                "unexpected CA crt FP {crt_fp:x?}, expected: {expected_fp:x?}"
            )));
        }

        String::from_utf8(crt.to_pem().context("generate PEM CA crt byte slice")?)
            .context("PEM CA crt byte slice as String")?
            .try_into()
            .context("PEM CA crt string as NonEmpty variant")
    }
}

const AIKIDO_SECRET_ROOT_CA_KEY: &str = "tls-root-ca-key";
const AIKIDO_SECRET_ROOT_CA_CRT: &str = "proxy-ca-crt";

pub(super) fn new_root_tls_crt_key_pair(
    secrets: &SyncSecrets,
    data_storage: &SyncCompactDataStorage,
) -> Result<PemKeyCrtPair, OpaqueError> {
    if let Some(key_data) = secrets.load_secret::<DataProxyRootCAKey>(AIKIDO_SECRET_ROOT_CA_KEY)? {
        // NOTE if we want to make this more resilient we can if cert is no longer found
        // try to recover it from system certificate storage. See note at the end of this file.
        tracing::debug!("root ca key found — assumption: Cert MUST exist as well!");
        let data_storage: DataProxyRootCACrt = data_storage
            .load(AIKIDO_SECRET_ROOT_CA_CRT)
            .context("read root ca crt data")?
            .context("assume root ca crt exists")?;
        tracing::debug!("root ca crt found... re-encoding it all so callee can make use of it");

        let crt = data_storage
            .try_crt_as_pem(key_data.crt_fingerprint())
            .context("compute PEM for found crt in data")?;

        let key = String::from_utf8(
            PKey::private_key_from_der(key_data.key())
                .context("parse (secret) private key from DER")?
                .private_key_to_pem_pkcs8()
                .context("generate PEM CA key byte slice")?,
        )
        .context("PEM CA key byte slice as String")?
        .try_into()
        .context("PEM CA key string as NonEmpty variant")?;

        return Ok(PemKeyCrtPair { crt, key });
    }

    tracing::debug!("no CA key was present in secret storage, generate + store pair now...");

    let (crt, key) = self_signed_server_ca(&SelfSignedData {
        organisation_name: Some("Aikido safe-chain proxy".to_owned()),
        common_name: Some(Domain::from_static("aikidosafechain.com")),
        subject_alternative_names: None,
    })
    .context("generate self signed TLS CA")?;

    let crt_fp = crt
        .digest(MessageDigest::sha256())
        .context("compute CA crt fingerprint (digest)")?
        .to_vec();

    let key_data = DataProxyRootCAKey::V1 {
        key: key
            .private_key_to_der_pkcs8()
            .context("generate DER CA key byte slice")?,
        fp: crt_fp,
    };
    let crt_data = DataProxyRootCACrt::V1 {
        crt: crt.to_der().context("generate DER CA crt byte slice")?,
    };

    tracing::trace!("key + crt data blobs ready for storage in secret/data storage backends...");

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

    tracing::trace!(
        "CA PEM pair ready for consumption, once and only once they are also stored..."
    );

    secrets
        .store_secret(AIKIDO_SECRET_ROOT_CA_KEY, &key_data)
        .context("store self-generated CA key+fp in secret storage")?;

    data_storage
        .store(AIKIDO_SECRET_ROOT_CA_CRT, &crt_data)
        .context("store self-generated CA crt in data storage")?;

    Ok(pair)
}

// NOTE:
//
// For now it is agreed and assumed that the Proxy (safechain-proxy)
// generates the root CA as well as the server CA. While at the same time
// the proxy is at the moment (by design) not responsible for
// "installing" the root CA.
//
// It is assumed that the agent (or related software other than the Proxy)
// fetches the CA (PEM) cert from the (proxy) meta server at path '/ca'
// and install the cert on behalf of the user (requires sudo-like permissions).
//
// In case the proxy should at some point be capable of installing the root CA as well,
// this is how it can be done:
//
// - For Windows we would make use of `schannel` support for it,
//   by using the API provided in the `schannel` crate:
//   <https://docs.rs/schannel/latest/schannel/cert_store/index.html>;
//
// - For MacOS we would need to use the "security framework" SDK,
//   for which this crate <https://docs.rs/security-framework/latest/security_framework/index.html>
//   provides all we need here
//
// - For Linux distributions there is no standard crate and instead we would
//   need to provide a solution on a distro by distro base...
//
//   E.g. for Ubuntu/Debian we
//   we would most likely want to use a CLI (child) process (call) such as:
//   ```shell
//   cp <my-ca> /usr/local/share/ca-certificates/ # this can be done via rust ofc
//   sudo update-ca-certificates  # this we would require to run via a child command
//   # when the command finishes the cert is installed
//   ```
//
// NOTE 2
//
// We can use the above SDK support also to recover the CA crt in case
// it was deleted (for some reason) from the proxy "data" (FS) dir...
//
// Both notes are here for instruction for future developers/maintainers of this project,
// as tasks to pick up when the need arises if at that point it still is the right choice.

#[cfg(test)]
mod tests {
    use crate::test::tmp_dir;

    use super::*;

    use rama::telemetry::tracing;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_new_root_tls_crt_key_pair_fs() {
        let dir = tmp_dir::try_new("test_new_root_tls_crt_key_pair_fs").unwrap();
        let secrets = SyncSecrets::new_fs(dir.clone());
        let data_storage = SyncCompactDataStorage::try_new(dir).unwrap();
        for _ in 0..2 {
            let _ = new_root_tls_crt_key_pair(&secrets, &data_storage).unwrap();
        }
    }
}
