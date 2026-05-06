use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rama::http::Uri;
use rama::{
    Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    http::{
        Body, BodyExtractExt as _, Method, Request, Response,
        header::{CONTENT_TYPE, HeaderValue},
    },
    telemetry::tracing,
    tls::boring::core::{
        asn1::Asn1Time,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        stack::Stack,
        x509::{
            X509, X509Name, X509Req,
            extension::{BasicConstraints, ExtendedKeyUsage},
        },
    },
};
use serde::{Deserialize, Serialize};

use super::RootCaKeyPair;
use crate::{
    storage::{SyncCompactDataStorage, SyncSecrets},
    utils::token::AgentIdentity,
};

mod storage;

use storage::{load_keypair_from_secret_storage, store_keypair_in_secret_storage};

const RENEWAL_THRESHOLD_SECS: u64 = 2 * 24 * 3600; // 2 days

fn needs_renewal(not_after_unix: i64) -> bool {
    let threshold = SystemTime::now() + Duration::from_secs(RENEWAL_THRESHOLD_SECS);
    let not_after = UNIX_EPOCH + Duration::from_secs(not_after_unix.max(0) as u64);
    threshold >= not_after
}

fn asn1_time_to_unix(t: &rama::tls::boring::core::asn1::Asn1TimeRef) -> Result<i64, BoxError> {
    let epoch = Asn1Time::from_unix(0).context("create unix epoch Asn1Time")?;
    let diff = epoch
        .diff(t)
        .context("compute diff from epoch to not_after")?;
    Ok(diff.days as i64 * 86400 + diff.secs as i64)
}

fn generate_ec_p256_key() -> Result<PKey<Private>, BoxError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("create EC P-256 group")?;
    let ec_key = EcKey::generate(&group).context("generate EC P-256 key")?;
    PKey::from_ec_key(ec_key).context("wrap EC key as PKey")
}

fn generate_int_ca_csr(device_id: &str, key: &PKey<Private>) -> Result<Vec<u8>, BoxError> {
    let mut builder = X509Req::builder().context("create X509Req builder")?;

    let mut name = X509Name::builder().context("create X509Name builder")?;
    name.append_entry_by_nid(Nid::COMMONNAME, device_id)
        .context("set CN in CSR subject")?;
    let name = name.build();
    builder
        .set_subject_name(&name)
        .context("set CSR subject name")?;

    builder.set_pubkey(key).context("set CSR public key")?;

    let mut exts = Stack::new().context("create extension stack")?;
    exts.push(
        BasicConstraints::new()
            .critical()
            .ca()
            .pathlen(0)
            .build()
            .context("build BasicConstraints extension")?,
    )
    .context("push BasicConstraints to stack")?;
    exts.push(
        ExtendedKeyUsage::new()
            .server_auth()
            .build()
            .context("build ExtendedKeyUsage extension")?,
    )
    .context("push ExtendedKeyUsage to stack")?;

    builder
        .add_extensions(&exts)
        .context("add extensions to CSR")?;

    builder
        .sign(key, MessageDigest::sha256())
        .context("sign CSR")?;

    builder.build().to_pem().context("encode CSR as PEM")
}

#[derive(Serialize)]
struct SignCsrRequest<'a> {
    csr: &'a str,
}

#[derive(Deserialize)]
struct SignCsrResponse {
    cert: String,
}

async fn fetch_signed_cert<C>(
    aikido_url: &Uri,
    identity: &AgentIdentity,
    csr_pem: &[u8],
    http_client: &C,
) -> Result<Vec<u8>, BoxError>
where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    let csr_str = std::str::from_utf8(csr_pem).context("CSR PEM is valid UTF-8")?;

    let sign_url = format!(
        "{}/pki/sign-csr",
        aikido_url.to_string().trim_end_matches('/')
    );
    let body_str = serde_json::to_string(&SignCsrRequest { csr: csr_str })
        .context("serialize sign-csr body")?;

    let mut req = Request::builder()
        .method(Method::POST)
        .uri(sign_url.as_str())
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(Body::from(body_str))
        .context("build sign-csr HTTP request")?;

    identity
        .add_request_headers(&mut req)
        .context("add identity headers to sign-csr request")?;

    let resp = http_client
        .serve(req)
        .await
        .context("POST to sign-csr endpoint")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.try_into_string().await.unwrap_or_default();
        return Err(OpaqueError::from_static_str("sign-csr request failed")
            .context_field("status", status)
            .context_field("body", body)
            .into_box_error());
    }

    let body = resp
        .try_into_string()
        .await
        .context("read sign-csr response body")?;
    let parsed: SignCsrResponse =
        serde_json::from_str(&body).context("parse sign-csr response JSON")?;

    Ok(parsed.cert.into_bytes())
}

pub(super) async fn load_or_create_int_ca_key_pair<C>(
    secrets: &SyncSecrets,
    _data_storage: &SyncCompactDataStorage,
    identity: &AgentIdentity,
    aikido_url: &Uri,
    http_client: &C,
) -> Result<RootCaKeyPair, BoxError>
where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    // NOTE: --use-aikido-ca is only meaningful on macOS.
    // Adding a self-signed CA to the macOS system trust store requires root/admin
    // privileges (sudo security add-trusted-cert ...), which the proxy does not have.
    // The Aikido intermediate CA is already trusted on enrolled devices via the device
    // enrollment flow, avoiding the need for elevated permissions.
    // On other platforms this function is not called — see proxy-bin-l4/src/tcp/mod.rs.

    if let Some((key_der, crt_der, not_after_unix)) =
        load_keypair_from_secret_storage(secrets)
            .context("load int CA keypair from secret storage")?
    {
        if !needs_renewal(not_after_unix) {
            tracing::debug!("int CA keypair found and not due for renewal, reusing");
            let crt_x509 = X509::from_der(&crt_der)
                .context("parse stored int CA cert from DER")?;
            let private_key = PKey::private_key_from_der(&key_der)
                .context("parse stored int CA private key from DER")?;
            return Ok(RootCaKeyPair::new(crt_x509, private_key));
        }
        tracing::info!("int CA cert is due for renewal, generating new keypair");
    } else {
        tracing::debug!("no int CA keypair in secret storage, generating new one");
    }

    // Generate new keypair, build CSR, get signed cert from Aikido Core
    let private_key = generate_ec_p256_key().context("generate ECDSA P-256 key")?;

    let device_id = identity.device_id();
    let csr_pem =
        generate_int_ca_csr(device_id, &private_key).context("generate intermediate CA CSR")?;

    tracing::debug!(device_id, "submitting CSR to Aikido Core for signing");
    let cert_pem = fetch_signed_cert(aikido_url, identity, &csr_pem, http_client)
        .await
        .context("fetch signed intermediate CA cert from Aikido Core")?;

    let crt_x509 =
        X509::from_pem(&cert_pem).context("parse signed intermediate CA cert from PEM")?;

    let crt_fp = crt_x509
        .digest(MessageDigest::sha256())
        .context("compute int CA cert fingerprint")?
        .to_vec();

    let not_after_unix =
        asn1_time_to_unix(crt_x509.not_after()).context("extract not_after from int CA cert")?;

    tracing::info!(
        not_after_unix,
        "intermediate CA cert signed successfully, storing keypair"
    );

    let key_der = private_key
        .private_key_to_der_pkcs8()
        .context("encode int CA private key to DER PKCS#8")?;

    let crt_der = crt_x509.to_der().context("encode int CA cert to DER")?;

    store_keypair_in_secret_storage(secrets, key_der, crt_der, crt_fp, not_after_unix)
        .context("store int CA keypair in secret storage")?;

    Ok(RootCaKeyPair::new(crt_x509, private_key))
}

#[cfg(test)]
mod tests;
