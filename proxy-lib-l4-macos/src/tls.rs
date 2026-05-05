//! MITM CA generation, persistence, and migration for the L4 transparent
//! proxy sysext.
//!
//! ## Storage model
//!
//! The active CA is encrypted with a Secure-Enclave-protected P-256 key and
//! stored in the macOS **System Keychain** (`/Library/Keychains/System.keychain`).
//! Three entries make up the bundle:
//!
//! | Service | Purpose |
//! |---|---|
//! | `aikido-l4-mitm-ca-se-key` | SE key `dataRepresentation` (envelope) |
//! | `aikido-l4-mitm-ca-crt`    | SE-encrypted CA cert PEM |
//! | `aikido-l4-mitm-ca-key`    | SE-encrypted CA key PEM |
//!
//! The Secure Enclave is **mandatory** on this path. If the host hardware
//! does not have a usable SE, [`load_or_create_active_ca`] returns a hard
//! error — we deliberately do not fall back to plaintext keychain storage,
//! because that would silently downgrade the security guarantee callers are
//! expecting.
//!
//! ## Legacy passthrough (graceful period)
//!
//! Older container builds generated the CA themselves and forwarded the
//! plaintext PEMs through the opaque config. Those PEMs are considered
//! polluted (they passed through a less-trusted boundary) and we must NOT
//! persist them in the SE-encrypted store. When [`load_or_create_active_ca`]
//! receives `legacy_pems`, it parses + uses them for this run only, leaves
//! the SE-encrypted slots untouched, and emits a deprecation warning. The
//! caller is expected to issue `generate-ca-crt` + `commit-ca-crt` to retire
//! the legacy CA at its earliest convenience.
//!
//! ## Module shape
//!
//! Two entry points:
//!
//! - [`load_or_create_active_ca`] — boot path. Returns an `ActiveCa` ready to
//!   be wrapped in [`crate::state::LiveCa`].
//! - [`generate_pending_ca`] — XPC `generate-ca-crt` path. Mints fresh
//!   key + cert in memory; **does not** touch the keychain.
//!
//! Plus [`persist_pending_ca`], used by the XPC `commit-ca-crt` route to
//! encrypt and store a [`crate::state::PendingCa`] before the relay swap.

use rama::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    net::{
        address::Domain,
        apple::networkextension::system_keychain::{
            self,
            secure_enclave::{
                SecureEnclaveAccessibility, SecureEnclaveKey, is_available as se_is_available,
            },
        },
        tls::server::SelfSignedData,
    },
    telemetry::tracing,
    tls::boring::{
        core::{
            pkey::{PKey, Private},
            x509::X509,
        },
        proxy::TlsMitmRelay,
        server::utils::self_signed_server_auth_gen_ca,
    },
};

use crate::state::{ActiveCa, PendingCa};

const CA_ACCOUNT: &str = "com.aikido.endpoint.proxy.l4";
const CA_SERVICE_CERT: &str = "aikido-l4-mitm-ca-crt";
const CA_SERVICE_KEY: &str = "aikido-l4-mitm-ca-key";
const SE_SERVICE_KEY: &str = "aikido-l4-mitm-ca-se-key";

const CA_COMMON_NAME: &str = "aikido-l4-mitm-ca.localhost";
const CA_ORG_NAME: &str = "Aikido Endpoint L4 Proxy Root CA";

/// Boot-path resolver for the active MITM CA.
///
/// `legacy_pems` carries `(cert_pem, key_pem)` forwarded through the opaque
/// config by the container app for the graceful-migration period. When set,
/// those PEMs are used **for this run only** and are *not* written to the
/// SE-encrypted system keychain — they are considered polluted, and the
/// caller is expected to rotate them out via the XPC commands.
///
/// In all other cases the SE-encrypted system keychain is the source of
/// truth: the existing CA is loaded, or — on first boot / after
/// `delete-ca-crt` — a fresh CA is minted and persisted.
///
/// Hard-errors when the host hardware does not expose a usable Secure Enclave.
pub(crate) fn load_or_create_active_ca(
    legacy_pems: Option<(&str, &str)>,
) -> Result<ActiveCa, BoxError> {
    if let Some((cert_pem, key_pem)) = legacy_pems {
        tracing::warn!(
            "DEPRECATED: using legacy MITM CA forwarded by the container app via opaque \
             config. The legacy CA will NOT be persisted in the SE-encrypted system keychain. \
             Caller should rotate it out via `generate-ca-crt` + `commit-ca-crt` as soon as \
             possible."
        );
        let cert = X509::from_pem(cert_pem.as_bytes())
            .context("parse legacy MITM CA cert PEM from opaque config")?;
        let key = PKey::private_key_from_pem(key_pem.as_bytes())
            .context("parse legacy MITM CA key PEM from opaque config")?;
        return active_ca_from_pair(cert, key);
    }

    require_secure_enclave()?;

    if let Some((cert, key)) = try_load_se_encrypted_ca()? {
        tracing::info!(
            cert_service = CA_SERVICE_CERT,
            key_service = CA_SERVICE_KEY,
            se_service = SE_SERVICE_KEY,
            account = CA_ACCOUNT,
            "loaded MITM CA from SE-encrypted system keychain"
        );
        return active_ca_from_pair(cert, key);
    }

    tracing::info!(
        "no MITM CA found in SE-encrypted system keychain; minting + persisting a fresh one"
    );
    let pending = generate_pending_ca()?;
    persist_pending_ca(&pending)?;
    active_ca_from_pending(&pending)
}

/// Mint a fresh MITM CA key + cert in memory.
///
/// Does **not** touch the keychain. The returned [`PendingCa`] is what the
/// XPC `generate-ca-crt` route hands back to callers and parks in
/// [`crate::state::LiveCa::pending`].
pub(crate) fn generate_pending_ca() -> Result<PendingCa, BoxError> {
    let (cert, key) = self_signed_server_auth_gen_ca(&SelfSignedData {
        organisation_name: Some(CA_ORG_NAME.to_owned()),
        common_name: Some(Domain::from_static(CA_COMMON_NAME)),
        ..Default::default()
    })
    .context("generate self-signed MITM CA")?;

    let cert_pem = cert.to_pem().context("encode MITM CA cert to PEM")?;
    let cert_der = cert.to_der().context("encode MITM CA cert to DER")?;

    Ok(PendingCa {
        cert,
        key,
        cert_pem: Bytes::from(cert_pem),
        cert_der: Bytes::from(cert_der),
    })
}

/// Encrypt + persist a pending CA in the SE-encrypted system keychain.
///
/// Used by the XPC `commit-ca-crt` route immediately before swapping the
/// active relay. Any failure here aborts the rotation: the old CA stays
/// active and the keychain is best-effort cleaned of partial state so the
/// next attempt starts from a clean slate.
pub(crate) fn persist_pending_ca(pending: &PendingCa) -> Result<(), BoxError> {
    require_secure_enclave()?;

    let key_pem = pending
        .key
        .private_key_to_pem_pkcs8()
        .context("encode MITM CA private key to PEM (PKCS#8)")?;

    let se_key = SecureEnclaveKey::create(SecureEnclaveAccessibility::Always)
        .context("mint Secure Enclave P-256 key for MITM CA")?;

    let cert_envelope = se_key
        .encrypt(&pending.cert_pem)
        .context("encrypt MITM CA cert PEM with Secure Enclave")?;
    let key_envelope = se_key
        .encrypt(&key_pem)
        .context("encrypt MITM CA key PEM with Secure Enclave")?;

    if let Err(err) = store_all(se_key.data_representation(), &cert_envelope, &key_envelope) {
        tracing::error!(
            error = %err,
            "failed to persist SE-encrypted MITM CA in system keychain; wiping partial state"
        );
        let _ = wipe_se_encrypted_ca();
        return Err(err);
    }

    tracing::info!(
        cert_service = CA_SERVICE_CERT,
        key_service = CA_SERVICE_KEY,
        se_service = SE_SERVICE_KEY,
        account = CA_ACCOUNT,
        cert_envelope_len = cert_envelope.len(),
        key_envelope_len = key_envelope.len(),
        se_blob_len = se_key.data_representation().len(),
        "persisted SE-encrypted MITM CA in system keychain"
    );

    Ok(())
}

fn store_all(se_blob: &[u8], cert_envelope: &[u8], key_envelope: &[u8]) -> Result<(), BoxError> {
    system_keychain::store_secret(SE_SERVICE_KEY, CA_ACCOUNT, se_blob)
        .context("store Secure Enclave key blob in system keychain")?;
    system_keychain::store_secret(CA_SERVICE_CERT, CA_ACCOUNT, cert_envelope)
        .context("store SE-encrypted MITM CA cert in system keychain")?;
    system_keychain::store_secret(CA_SERVICE_KEY, CA_ACCOUNT, key_envelope)
        .context("store SE-encrypted MITM CA key in system keychain")?;
    Ok(())
}

fn try_load_se_encrypted_ca() -> Result<Option<(X509, PKey<Private>)>, BoxError> {
    let se_blob = load_secret(SE_SERVICE_KEY)?;
    let cert_blob = load_secret(CA_SERVICE_CERT)?;
    let key_blob = load_secret(CA_SERVICE_KEY)?;

    let presence = (se_blob.is_some(), cert_blob.is_some(), key_blob.is_some());

    let (Some(se_blob), Some(cert_blob), Some(key_blob)) = (se_blob, cert_blob, key_blob) else {
        let present_count = u8::from(presence.0) + u8::from(presence.1) + u8::from(presence.2);
        if present_count > 0 {
            tracing::warn!(
                se_blob_present = presence.0,
                cert_blob_present = presence.1,
                key_blob_present = presence.2,
                "incomplete SE-encrypted MITM CA state in system keychain; wiping and \
                 regenerating"
            );
            let _ = wipe_se_encrypted_ca();
        }
        return Ok(None);
    };

    let se_key = SecureEnclaveKey::from_data_representation(se_blob);
    match decrypt_pair(&se_key, &cert_blob, &key_blob) {
        Ok(pair) => Ok(Some(pair)),
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to decrypt SE-encrypted MITM CA from system keychain; wiping all \
                 entries and regenerating"
            );
            let _ = wipe_se_encrypted_ca();
            Ok(None)
        }
    }
}

fn decrypt_pair(
    se_key: &SecureEnclaveKey,
    cert_envelope: &[u8],
    key_envelope: &[u8],
) -> Result<(X509, PKey<Private>), BoxError> {
    let cert_pem = se_key
        .decrypt(cert_envelope)
        .context("decrypt MITM CA cert with Secure Enclave")?;
    let key_pem = se_key
        .decrypt(key_envelope)
        .context("decrypt MITM CA key with Secure Enclave")?;
    let cert = X509::from_pem(&cert_pem).context("parse decrypted MITM CA cert PEM")?;
    let key = PKey::private_key_from_pem(&key_pem).context("parse decrypted MITM CA key PEM")?;
    Ok((cert, key))
}

fn load_secret(service: &str) -> Result<Option<Vec<u8>>, BoxError> {
    system_keychain::load_secret(service, CA_ACCOUNT)
        .with_context(|| format!("load `{service}` from system keychain"))
}

fn wipe_se_encrypted_ca() -> Result<(), BoxError> {
    let mut last_err: Option<BoxError> = None;
    for service in [SE_SERVICE_KEY, CA_SERVICE_CERT, CA_SERVICE_KEY] {
        if let Err(err) = system_keychain::delete_secret(service, CA_ACCOUNT) {
            let boxed: BoxError = Box::new(err);
            last_err = Some(
                Result::<(), BoxError>::Err(boxed)
                    .with_context(|| format!("delete `{service}` from system keychain"))
                    .unwrap_err(),
            );
        }
    }
    match last_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn require_secure_enclave() -> Result<(), BoxError> {
    if se_is_available() {
        return Ok(());
    }
    Err(OpaqueError::from_static_str(
        "Secure Enclave unavailable on this Mac; the L4 transparent proxy refuses to \
         operate without SE-protected MITM CA storage. Affected hardware: Intel Macs \
         without a T2 chip and any host where the SE is otherwise disabled. Contact \
         Aikido support for next steps.",
    )
    .into_box_error())
}

fn active_ca_from_pair(cert: X509, key: PKey<Private>) -> Result<ActiveCa, BoxError> {
    let cert_pem = cert.to_pem().context("encode active MITM CA cert to PEM")?;
    let cert_der = cert.to_der().context("encode active MITM CA cert to DER")?;
    Ok(ActiveCa {
        relay: TlsMitmRelay::new_cached_in_memory(cert, key),
        cert_pem: Bytes::from(cert_pem),
        cert_der: Bytes::from(cert_der),
    })
}

fn active_ca_from_pending(pending: &PendingCa) -> Result<ActiveCa, BoxError> {
    Ok(ActiveCa {
        relay: TlsMitmRelay::new_cached_in_memory(pending.cert.clone(), pending.key.clone()),
        cert_pem: pending.cert_pem.clone(),
        cert_der: pending.cert_der.clone(),
    })
}
