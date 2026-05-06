// The intermediate CA keypair (private key + signed cert) is stored as a single
// Keychain entry. Apple Keychain has no practical per-entry size limit for a DER
// cert (typically ~1-3 KB), so the chunked storage used by some other backends is
// unnecessary here.

use rama::{
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    tls::boring::core::{hash::MessageDigest, x509::X509},
};
use serde::{Deserialize, Serialize};

use crate::storage::SyncSecrets;

const AIKIDO_SECRET_INT_CA_KEYPAIR: &str = "tls-int-ca-keypair";

#[derive(Serialize, Deserialize)]
enum DataProxyIntCAKeyPair {
    V1 {
        key_der: Vec<u8>,
        crt_der: Vec<u8>,
        fp: Vec<u8>,        // SHA-256 of crt_der, verified on load to catch corruption
        not_after_unix: i64,
    },
}

pub(super) fn store_keypair_in_secret_storage(
    secrets: &SyncSecrets,
    key_der: Vec<u8>,
    crt_der: Vec<u8>,
    fp: Vec<u8>,
    not_after_unix: i64,
) -> Result<(), BoxError> {
    let keypair = DataProxyIntCAKeyPair::V1 {
        key_der,
        crt_der,
        fp,
        not_after_unix,
    };
    secrets
        .store_secret(AIKIDO_SECRET_INT_CA_KEYPAIR, &keypair)
        .context("store int CA keypair in secret storage")
}

/// Returns `(key_der, crt_der, not_after_unix)` if a valid keypair is found,
/// `None` if no entry exists, or an error if the stored fingerprint does not
/// match the loaded certificate.
pub(super) fn load_keypair_from_secret_storage(
    secrets: &SyncSecrets,
) -> Result<Option<(Vec<u8>, Vec<u8>, i64)>, BoxError> {
    let Some(keypair) =
        secrets.load_secret::<DataProxyIntCAKeyPair>(AIKIDO_SECRET_INT_CA_KEYPAIR)?
    else {
        return Ok(None);
    };

    let DataProxyIntCAKeyPair::V1 {
        key_der,
        crt_der,
        fp: stored_fp,
        not_after_unix,
    } = keypair;

    let crt_x509 = X509::from_der(&crt_der).context("parse stored int CA cert from DER")?;
    let computed_fp = crt_x509
        .digest(MessageDigest::sha256())
        .context("recompute int CA cert fingerprint")?;

    if !computed_fp.eq(stored_fp.as_slice()) {
        return Err(
            OpaqueError::from_static_str("stored int CA cert fingerprint mismatch")
                .context_hex_field("computed_fp", computed_fp)
                .context_hex_field("stored_fp", stored_fp),
        );
    }

    Ok(Some((key_der, crt_der, not_after_unix)))
}
