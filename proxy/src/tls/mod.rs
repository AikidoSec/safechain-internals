use std::sync::Arc;

use rama::{
    error::{ErrorContext, OpaqueError},
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

use crate::Args;

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

pub fn new_tls_acceptor_layer(args: &Args) -> Result<(TlsAcceptorLayer, RootCA), OpaqueError> {
    let PemKeyCrtPair { crt, key } = self::root::new_root_tls_crt_key_pair(&args.secrets)?;

    let root_ca = RootCA(Arc::new(SecretBox::new(Box::new(crt.as_ref().to_owned()))));

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
