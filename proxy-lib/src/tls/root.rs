use rama::{
    error::{BoxError, ErrorContext as _, ErrorExt as _},
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
    fn crt_der(&self) -> &[u8] {
        match self {
            DataProxyRootCACrt::V1 { crt } => crt.as_slice(),
        }
    }

    fn try_crt_as_pem(&self, expected_fp: &[u8]) -> Result<NonEmptyStr, BoxError> {
        let crt_der = self.crt_der();

        let crt = X509::from_der(crt_der).context("create x509 crt from read DER")?;
        let crt_fp = crt
            .digest(MessageDigest::sha256())
            .context("(re)compute CA crt fingerprint (digest) for verification")?;

        if !crt_fp.eq(expected_fp) {
            return Err(BoxError::from("unexpected CA crt fingerprint")
                .context_hex_field("computed_fingerprint", crt_fp)
                .context_hex_field("expected_fingerprint", expected_fp.to_vec()));
        }

        String::from_utf8(crt.to_pem().context("generate PEM CA crt byte slice")?)
            .context("PEM CA crt byte slice as String")?
            .try_into()
            .context("PEM CA crt string as NonEmpty variant")
    }
}

const AIKIDO_SECRET_ROOT_CA_KEY: &str = "tls-root-ca-key";
const AIKIDO_SECRET_ROOT_CA_CRT_META: &str = "tls-root-ca-crt-meta";
const AIKIDO_SECRET_ROOT_CA_CRT_CHUNK_PREFIX: &str = "tls-root-ca-crt-chunk";
const AIKIDO_SECRET_ROOT_CA_CRT_LEGACY_DATA_KEY: &str = "proxy-ca-crt";
const CRT_SECRET_CHUNK_SIZE_BYTES: usize = 768;

#[derive(Serialize, Deserialize)]
enum DataProxyRootCACrtMeta {
    V1 { chunks: usize, fp: Vec<u8> },
}

impl DataProxyRootCACrtMeta {
    fn chunks(&self) -> usize {
        match self {
            DataProxyRootCACrtMeta::V1 { chunks, .. } => *chunks,
        }
    }

    fn crt_fingerprint(&self) -> &[u8] {
        match self {
            DataProxyRootCACrtMeta::V1 { fp, .. } => fp.as_slice(),
        }
    }
}

#[inline]
fn crt_chunk_secret_key(index: usize) -> String {
    format!("{AIKIDO_SECRET_ROOT_CA_CRT_CHUNK_PREFIX}-{index}")
}

fn store_crt_in_secret_storage(
    secrets: &SyncSecrets,
    crt_data: &DataProxyRootCACrt,
    crt_fp: &[u8],
) -> Result<(), BoxError> {
    let crt_der = crt_data.crt_der();
    let chunk_count = crt_der.len().div_ceil(CRT_SECRET_CHUNK_SIZE_BYTES);
    if chunk_count == 0 {
        return Err(BoxError::from(
            "refusing to store empty CA crt bytes in secret storage",
        ));
    }

    for (idx, chunk) in crt_der.chunks(CRT_SECRET_CHUNK_SIZE_BYTES).enumerate() {
        let chunk_key = crt_chunk_secret_key(idx);
        let chunk_vec = chunk.to_vec();
        secrets
            .store_secret(&chunk_key, &chunk_vec)
            .context("store CA crt chunk in secret storage")
            .context_str_field("chunk_key", &chunk_key)?;
    }

    let crt_meta = DataProxyRootCACrtMeta::V1 {
        chunks: chunk_count,
        fp: crt_fp.to_vec(),
    };
    secrets
        .store_secret(AIKIDO_SECRET_ROOT_CA_CRT_META, &crt_meta)
        .context("store CA crt meta in secret storage")
}

fn load_crt_from_secret_storage(
    secrets: &SyncSecrets,
    expected_fp: &[u8],
) -> Result<Option<DataProxyRootCACrt>, BoxError> {
    let Some(crt_meta) =
        secrets.load_secret::<DataProxyRootCACrtMeta>(AIKIDO_SECRET_ROOT_CA_CRT_META)?
    else {
        return Ok(None);
    };

    if !crt_meta.crt_fingerprint().eq(expected_fp) {
        return Err(BoxError::from("unexpected CA crt meta fingerprint")
            .context_hex_field("expected_fingerprint", expected_fp.to_vec())
            .context_hex_field("found_fingerprint", crt_meta.crt_fingerprint().to_vec()));
    }

    let mut crt_der = Vec::new();
    for idx in 0..crt_meta.chunks() {
        let chunk_key = crt_chunk_secret_key(idx);
        let Some(chunk) = secrets
            .load_secret::<Vec<u8>>(&chunk_key)
            .context("load CA crt chunk from secret storage")
            .context_str_field("chunk_key", &chunk_key)?
        else {
            return Err(BoxError::from("missing CA crt chunk in secret storage")
                .context_str_field("chunk_key", &chunk_key));
        };
        crt_der.extend_from_slice(&chunk);
    }

    Ok(Some(DataProxyRootCACrt::V1 { crt: crt_der }))
}

pub(super) fn new_root_tls_crt_key_pair(
    secrets: &SyncSecrets,
    data_storage: &SyncCompactDataStorage,
) -> Result<PemKeyCrtPair, BoxError> {
    if let Some(key_data) = secrets.load_secret::<DataProxyRootCAKey>(AIKIDO_SECRET_ROOT_CA_KEY)? {
        tracing::debug!("root ca key found — load matching crt from secret storage");
        let crt_data = match load_crt_from_secret_storage(secrets, key_data.crt_fingerprint())
            .context("load root ca crt from secret storage")?
        {
            Some(crt_data) => crt_data,
            None => {
                // NOTE: in future we can remove this fallback,
                // as this is only to be backwards compatible with older apps..
                tracing::warn!(
                    "root ca crt not found in secret storage; trying legacy fs data storage fallback"
                );
                let legacy_crt_data: DataProxyRootCACrt = data_storage
                    .load(AIKIDO_SECRET_ROOT_CA_CRT_LEGACY_DATA_KEY)
                    .context("read legacy root ca crt data")?
                    .context("assume legacy root ca crt exists")?;
                store_crt_in_secret_storage(secrets, &legacy_crt_data, key_data.crt_fingerprint())
                    .context("migrate legacy root ca crt from data storage to secret storage")?;
                legacy_crt_data
            }
        };
        tracing::debug!("root ca crt found... re-encoding it all so callee can make use of it");

        let crt = crt_data
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

    tracing::trace!("key + crt data blobs ready for storage in secret storage backend...");

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

    store_crt_in_secret_storage(secrets, &crt_data, key_data.crt_fingerprint())
        .context("store self-generated CA crt in secret storage")?;

    Ok(pair)
}

// NOTE:
//
// For now it is agreed and assumed that the Proxy (e.g. endpoint-protection-l7-proxy)
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
    use crate::utils::io::tmp_dir;

    use super::*;

    use rama::telemetry::tracing;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_new_root_tls_crt_key_pair_fs() {
        let dir = tmp_dir::try_new("test_new_root_tls_crt_key_pair_fs").unwrap();
        let secrets =
            SyncSecrets::try_new_fs(crate::utils::env::project_name(), dir.clone()).unwrap();
        let data_storage = SyncCompactDataStorage::try_new(dir).unwrap();
        for _ in 0..2 {
            let _ = new_root_tls_crt_key_pair(&secrets, &data_storage).unwrap();
        }
    }
}
