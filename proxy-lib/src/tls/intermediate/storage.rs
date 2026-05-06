// Certs can be a few KB, which exceeds the per-entry size limit of some secret storage
// backends. We therefore split the DER-encoded cert into fixed-size chunks and write
// each chunk under its own key. A separate metadata entry records the chunk count,
// the cert fingerprint (for integrity verification), and the expiry timestamp.

use rama::error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError};
use serde::{Deserialize, Serialize};

use crate::storage::SyncSecrets;

const AIKIDO_SECRET_INT_CA_CRT_META: &str = "tls-int-ca-crt-meta";
const AIKIDO_SECRET_INT_CA_CRT_CHUNK_PREFIX: &str = "tls-int-ca-crt-chunk";
const CRT_SECRET_CHUNK_SIZE_BYTES: usize = 768;

#[derive(Serialize, Deserialize)]
pub(super) enum DataProxyIntCACrt {
    V1 { crt: Vec<u8> },
}

impl DataProxyIntCACrt {
    pub(super) fn crt_der(&self) -> &[u8] {
        match self {
            DataProxyIntCACrt::V1 { crt } => crt.as_slice(),
        }
    }
}

#[derive(Serialize, Deserialize)]
enum DataProxyIntCACrtMeta {
    V1 {
        chunks: usize,
        fp: Vec<u8>,
        not_after_unix: i64,
    },
}

impl DataProxyIntCACrtMeta {
    fn chunks(&self) -> usize {
        match self {
            DataProxyIntCACrtMeta::V1 { chunks, .. } => *chunks,
        }
    }

    fn crt_fingerprint(&self) -> &[u8] {
        match self {
            DataProxyIntCACrtMeta::V1 { fp, .. } => fp.as_slice(),
        }
    }

    fn not_after_unix(&self) -> i64 {
        match self {
            DataProxyIntCACrtMeta::V1 { not_after_unix, .. } => *not_after_unix,
        }
    }
}

fn crt_chunk_secret_key(index: usize) -> String {
    format!("{AIKIDO_SECRET_INT_CA_CRT_CHUNK_PREFIX}-{index}")
}

pub(super) fn store_crt_in_secret_storage(
    secrets: &SyncSecrets,
    crt_data: &DataProxyIntCACrt,
    crt_fp: &[u8],
    not_after_unix: i64,
) -> Result<(), BoxError> {
    let crt_der = crt_data.crt_der();
    let chunk_count = crt_der.len().div_ceil(CRT_SECRET_CHUNK_SIZE_BYTES);
    if chunk_count == 0 {
        return Err(OpaqueError::from_static_str(
            "refusing to store empty int CA crt bytes in secret storage",
        )
        .into_box_error());
    }

    for (idx, chunk) in crt_der.chunks(CRT_SECRET_CHUNK_SIZE_BYTES).enumerate() {
        let chunk_key = crt_chunk_secret_key(idx);
        let chunk_vec = chunk.to_vec();
        secrets
            .store_secret(&chunk_key, &chunk_vec)
            .context("store int CA crt chunk in secret storage")
            .context_str_field("chunk_key", &chunk_key)?;
    }

    let crt_meta = DataProxyIntCACrtMeta::V1 {
        chunks: chunk_count,
        fp: crt_fp.to_vec(),
        not_after_unix,
    };
    secrets
        .store_secret(AIKIDO_SECRET_INT_CA_CRT_META, &crt_meta)
        .context("store int CA crt meta in secret storage")
}

pub(super) fn load_crt_from_secret_storage(
    secrets: &SyncSecrets,
    expected_fp: &[u8],
) -> Result<Option<(DataProxyIntCACrt, i64)>, BoxError> {
    let Some(crt_meta) =
        secrets.load_secret::<DataProxyIntCACrtMeta>(AIKIDO_SECRET_INT_CA_CRT_META)?
    else {
        return Ok(None);
    };

    if !crt_meta.crt_fingerprint().eq(expected_fp) {
        return Err(
            OpaqueError::from_static_str("unexpected int CA crt meta fingerprint")
                .context_hex_field("expected_fingerprint", expected_fp.to_vec())
                .context_hex_field("found_fingerprint", crt_meta.crt_fingerprint().to_vec()),
        );
    }

    let not_after_unix = crt_meta.not_after_unix();

    let mut crt_der = Vec::new();
    for idx in 0..crt_meta.chunks() {
        let chunk_key = crt_chunk_secret_key(idx);
        let Some(chunk) = secrets
            .load_secret::<Vec<u8>>(&chunk_key)
            .context("load int CA crt chunk from secret storage")
            .context_str_field("chunk_key", &chunk_key)?
        else {
            return Err(
                OpaqueError::from_static_str("missing int CA crt chunk in secret storage")
                    .context_str_field("chunk_key", &chunk_key),
            );
        };
        crt_der.extend_from_slice(&chunk);
    }

    Ok(Some((
        DataProxyIntCACrt::V1 { crt: crt_der },
        not_after_unix,
    )))
}
