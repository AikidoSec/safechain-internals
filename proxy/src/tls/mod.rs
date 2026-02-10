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
    tls::boring::server::TlsAcceptorLayer,
    utils::str::NonEmptyStr,
};

use secrecy::{ExposeSecret, SecretBox};

use crate::{Args, storage::SyncCompactDataStorage};

mod root;

struct PemKeyCrtPair {
    pub crt: NonEmptyStr,
    pub key: NonEmptyStr,
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
    args: &Args,
    data_storage: &SyncCompactDataStorage,
) -> Result<(TlsAcceptorLayer, RootCA), BoxError> {
    let PemKeyCrtPair { crt, key } =
        self::root::new_root_tls_crt_key_pair(&args.secrets, data_storage)?;

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
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
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
