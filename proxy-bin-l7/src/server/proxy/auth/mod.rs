use std::{borrow::Cow, convert::Infallible, time::Duration};

use rama::{
    extensions::Extensions,
    http::{HeaderName, headers::authorization::AuthoritySync},
    net::user::{
        Basic, UserId,
        authority::{AuthorizeResult, Authorizer},
    },
    telemetry::tracing,
    username::{UsernameLabelParser, UsernameLabelState, parse_username},
    utils::str::smol_str::StrExt as _,
};

use serde::{Deserialize, de::Error};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ZeroAuthority;

impl ZeroAuthority {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

pub const HEADER_NAME_X_AIKIDO_SAFE_CHAIN_CONFIG: HeaderName =
    HeaderName::from_static("x-aikido-safe-chain-config");

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
        let mut parser_ext = Extensions::new();

        // The use of proxy authentication is a common practice for
        // proxy users to pass configs via a concept called username labels.
        // See `docs/proxy/auth-flow.md` for more informtion.
        let username_parser = (
            FirewallUserConfigParser::default(),
            (), // We make use use the void trailer parser to ensure we drop any ignored label.
        );

        let parsed_username = match parse_username(&mut parser_ext, username_parser, basic_username)
        {
            Ok(t) => {
                result_extensions.extend(parser_ext);
                t
            }
            Err(err) => {
                tracing::trace!("failed to parse username: {:?}", err);
                basic_username.to_owned()
            }
        };

        result_extensions.insert(UserId::Username(parsed_username));

        AuthorizeResult {
            credentials,
            result: Ok(Some(result_extensions)),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
/// Config which allows the user of the safechain-l7-proxy
/// by means of (proxy basic auth) username labels to adapt
/// some configuration for its connection(s).
pub struct FirewallUserConfig {
    pub min_package_age: Option<Duration>,
}

/// Human-friendly time parser.
///
/// Some examples are "5h", "5h 30m" and "5h_30m".
fn parse_humantime_str(s: &str) -> Result<Duration, humantime::DurationError> {
    let s = s.trim();
    if s.contains('_') {
        humantime::parse_duration(&s.replace_smolstr("_", " "))
    } else {
        humantime::parse_duration(s)
    }
}

impl<'de> Deserialize<'de> for FirewallUserConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Debug, Deserialize)]
        struct T<'a> {
            min_pkg_age: Option<Cow<'a, str>>,
        }

        let t = T::deserialize(deserializer)?;

        Ok(Self {
            min_package_age: t
                .min_pkg_age
                .as_deref()
                .map(parse_humantime_str)
                .transpose()
                .map_err(D::Error::custom)?,
        })
    }
}

#[derive(Debug, Clone, Default)]
/// [`UsernameLabelParser`] for [`FirewallUserConfig`].
pub struct FirewallUserConfigParser {
    state: FirewallUserConfigParserState,
    cfg: Option<FirewallUserConfig>,
}

#[derive(Debug, Clone, Default)]
enum FirewallUserConfigParserState {
    #[default]
    Key,
    ValueMinPackageAge,
}

impl UsernameLabelParser for FirewallUserConfigParser {
    type Error = Infallible;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        match self.state {
            FirewallUserConfigParserState::Key => {
                let label = label.trim();
                if label.eq_ignore_ascii_case("min_pkg_age") {
                    self.state = FirewallUserConfigParserState::ValueMinPackageAge;
                    return UsernameLabelState::Used;
                }

                UsernameLabelState::Ignored
            }
            FirewallUserConfigParserState::ValueMinPackageAge => match parse_humantime_str(label) {
                Ok(d) => {
                    tracing::trace!(
                        "firewall cfg min package age '{d:?}' (raw = '{label}') found in username label(s)"
                    );
                    self.cfg.get_or_insert_default().min_package_age = Some(d);
                    self.state = FirewallUserConfigParserState::Key;
                    UsernameLabelState::Used
                }
                Err(err) => {
                    tracing::debug!(
                        "firewall cfg invalid min package age value ('{label}') found in username label(s): {err}; abort username label parsing"
                    );
                    UsernameLabelState::Abort
                }
            },
        }
    }

    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
        if let Some(cfg) = self.cfg {
            tracing::debug!(
                "firewall cfg parsed and computed from username labels; insert {cfg:?} in extensions"
            );
            ext.insert(cfg);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
