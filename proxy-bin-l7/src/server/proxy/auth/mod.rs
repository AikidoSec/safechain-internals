use std::convert::Infallible;

use rama::{
    extensions::Extensions,
    http::headers::authorization::AuthoritySync,
    net::user::{
        Basic, UserId,
        authority::{AuthorizeResult, Authorizer},
    },
    telemetry::tracing,
    username::{UsernameLabelParser, parse_username},
};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ZeroAuthority;

impl ZeroAuthority {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

impl<T: UsernameLabelParser> AuthoritySync<Basic, T> for ZeroAuthority {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        let basic_username = credentials.username();
        tracing::trace!("ZeroAuthority (http proxy) trusts all, it also trusts: {basic_username}");

        let mut parser_ext = Extensions::new();
        let parsed_username = match parse_username(&mut parser_ext, T::default(), basic_username) {
            Ok(t) => {
                ext.extend(parser_ext);
                t
            }
            Err(err) => {
                tracing::trace!("failed to parse username: {:?}", err);
                basic_username.to_owned()
            }
        };
        ext.insert(UserId::Username(parsed_username));
        true
    }
}

impl Authorizer<Basic> for ZeroAuthority {
    type Error = Infallible;

    async fn authorize(&self, credentials: Basic) -> AuthorizeResult<Basic, Self::Error> {
        let basic_username = credentials.username();
        tracing::trace!(
            "ZeroAuthority (socks5 proxy) trusts all, it also trusts: {basic_username}"
        );

        let mut result_extensions = Extensions::new();
        result_extensions.insert(UserId::Username(basic_username.to_owned()));

        AuthorizeResult {
            credentials,
            result: Ok(Some(result_extensions)),
        }
    }
}
