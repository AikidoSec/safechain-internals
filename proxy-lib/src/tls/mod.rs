use std::sync::Arc;

use rama::{
    error::{BoxError, ErrorContext as _},
    http::{Response, service::web::response::IntoResponse},
    net::tls::{
        ApplicationProtocol, DataEncoding,
        server::{
            ServerAuth, ServerAuthData, ServerCertIssuerData, ServerCertIssuerKind, ServerConfig,
        },
    },
    tls::boring::{
        core::{
            pkey::{PKey, Private},
            x509::X509,
        },
        server::TlsAcceptorLayer,
    },
    utils::str::NonEmptyStr,
};

use secrecy::{ExposeSecret, SecretBox};

use crate::storage::{SyncCompactDataStorage, SyncSecrets};

pub mod mitm_relay_policy;
mod root;

#[derive(Clone)]
pub struct RootCaKeyPair {
    crt_pem: NonEmptyStr,
    key_pem: NonEmptyStr,
    crt_x509: X509,
    key_x509: PKey<Private>,
}

impl RootCaKeyPair {
    pub fn try_from_boring(
        certificate: X509,
        private_key: PKey<Private>,
    ) -> Result<Self, BoxError> {
        let crt_pem = String::from_utf8(
            certificate
                .to_pem()
                .context("encode CA certificate to PEM")?,
        )
        .context("CA certificate PEM is valid UTF-8")?
        .try_into()
        .context("CA certificate PEM is non-empty")?;
        let key_pem = String::from_utf8(
            private_key
                .private_key_to_pem_pkcs8()
                .context("encode CA private key to PKCS#8 PEM")?,
        )
        .context("CA private key PEM is valid UTF-8")?
        .try_into()
        .context("CA private key PEM is non-empty")?;

        Ok(Self {
            crt_pem,
            key_pem,
            crt_x509: certificate,
            key_x509: private_key,
        })
    }

    #[inline(always)]
    pub fn certificate_pem(&self) -> &NonEmptyStr {
        &self.crt_pem
    }

    #[inline(always)]
    pub fn private_key_pem(&self) -> &NonEmptyStr {
        &self.key_pem
    }

    #[inline(always)]
    pub fn certificate(&self) -> &X509 {
        &self.crt_x509
    }

    #[inline(always)]
    pub fn private_key(&self) -> &PKey<Private> {
        &self.key_x509
    }

    #[inline(always)]
    pub fn into_pair(self) -> (X509, PKey<Private>) {
        (self.crt_x509, self.key_x509)
    }
}

#[derive(Debug, Clone)]
pub struct RootCA(Arc<SecretBox<String>>);

impl RootCA {
    pub fn as_http_response(&self) -> Response {
        let ca = self.0.expose_secret();
        ca.clone().into_response()
    }
}

pub fn new_tls_acceptor_layer(
    secrets: &SyncSecrets,
    data_storage: &SyncCompactDataStorage,
    application_layer_protocol_negotiation: Option<Vec<ApplicationProtocol>>,
) -> Result<(TlsAcceptorLayer, RootCA), BoxError> {
    let root_ca_key_pair = load_or_create_root_ca_key_pair(secrets, data_storage)?;
    let crt = root_ca_key_pair.certificate_pem().clone();
    let key = root_ca_key_pair.private_key_pem().clone();

    let root_ca = RootCA(Arc::new(SecretBox::new(Box::new(crt.as_ref().to_owned()))));

    // NOTE:
    //
    // The TLS Acceptor for the Proxy setup (both the proxy, MITM server and Meta HTTP(S) server)
    // work based on:
    //
    // - a self-signed stored root CA (valid for 20 years) generated first time the proxy starts up,
    //   with the key (+ crt fingerprint) stored in the platform keyring, and crt itself
    //   stored in a compact binary format in the data folder
    //   - For now it is assumed this data folder will not be deleted,
    //     this can be made more resistent by "recovering" a crt from the relevant
    //     certificate storage in case the data folder was wiped or corrupted...
    //     This is to be actioned once required...
    //
    // - server (acceptor) certificates generated for each required domain,
    //   issued by the above root CA
    //
    // That said... In case for all or some use cases of the proxy you wish
    // to:
    //
    // a. derive the proxy CA from a remote CA
    // b. or have no CA in the proxy (env) at all...
    //
    // It is a possibility. Rama has support for remote issuers (required for (b))
    // or in case of (a) it would simply mean that the proxy CA would be requested
    // from a remote server instead of self-signing it as we do now.
    //
    // All is possible, over whatever web protocol, with whatever encryption standards,
    // and with as granular permissions, scoping and authentication that you might desire...
    // E.g. allow the proxy only to request crts (issued by a remote service)
    // for the domains its needs to MITM and nothing else... Etc...

    let tls_acceptor_data = ServerConfig {
        application_layer_protocol_negotiation,
        ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData {
            // NOTE: here we could use a (custom) dynamic issuer to easily
            // allow a remote TLS Crt Issuer, should we ever want to,
            // that can be implemented however we wish
            kind: ServerCertIssuerKind::Single(ServerAuthData {
                private_key: DataEncoding::Pem(key),
                cert_chain: DataEncoding::Pem(crt.clone()),
                ocsp: None,
            }),
            ..Default::default()
        }))
    }
    .try_into()
    .context("create tls acceptor data")?;

    Ok((
        TlsAcceptorLayer::new(tls_acceptor_data).with_store_client_hello(true),
        root_ca,
    ))
}

pub fn load_or_create_root_ca_key_pair(
    secrets: &SyncSecrets,
    data_storage: &SyncCompactDataStorage,
) -> Result<RootCaKeyPair, BoxError> {
    self::root::new_root_tls_crt_key_pair(secrets, data_storage)
}
