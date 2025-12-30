use std::{convert::Infallible, time::Duration};

use rama::{
    extensions::Extensions,
    http::headers::authorization::AuthoritySync,
    net::user::{
        Basic, UserId,
        authority::{AuthorizeResult, Authorizer},
    },
    telemetry::tracing,
    username::{UsernameLabelParser, UsernameLabelState, parse_username},
    utils::str::smol_str::StrExt as _,
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
        tracing::trace!("ZeroAuthority trusts all, it also trusts: {basic_username}");

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
        tracing::trace!("ZeroAuthority trusts all, it also trusts: {basic_username}");

        let mut result_extensions = Extensions::new();
        let mut parser_ext = Extensions::new();

        let parsed_username = match parse_username(
            &mut parser_ext,
            FirewallUserConfigParser::default(),
            basic_username,
        ) {
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
/// Config which allows the user of the safechain-proxy
/// by means of (proxy basic auth) username labels to adapt
/// some configuration for its connection(s).
pub struct FirewallUserConfig {
    min_package_age: Option<Duration>,
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
            FirewallUserConfigParserState::ValueMinPackageAge => {
                match humantime::parse_duration(&label.trim().replace_smolstr("_", " ")) {
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
                }
            }
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
mod tests {
    use super::*;

    #[test]
    #[tracing_test::traced_test]
    fn test_firewall_config_parsing() {
        struct TestCase {
            description: &'static str,
            io: &'static [(&'static str, UsernameLabelState)],
            expected_cfg: Option<FirewallUserConfig>,
        }

        for test_case in [
            TestCase {
                description: "no username labels",
                io: &[],
                expected_cfg: None,
            },
            TestCase {
                description: "ignored username label: foo",
                io: &[("foo", UsernameLabelState::Ignored)],
                expected_cfg: None,
            },
            TestCase {
                description: "ignored username labels: [foo, bar]",
                io: &[
                    ("foo", UsernameLabelState::Ignored),
                    ("bar", UsernameLabelState::Ignored),
                ],
                expected_cfg: None,
            },
            TestCase {
                description: "valid username labels: min_pkg_age-48h",
                io: &[
                    ("min_pkg_age", UsernameLabelState::Used),
                    ("48h", UsernameLabelState::Used),
                ],
                expected_cfg: Some(FirewallUserConfig {
                    min_package_age: Some(Duration::from_hours(48)),
                }),
            },
            TestCase {
                description: "valid username labels: min_pkg_age-48h (with ignored labels before and after)",
                io: &[
                    ("answer", UsernameLabelState::Ignored),
                    ("42", UsernameLabelState::Ignored),
                    ("min_pkg_age", UsernameLabelState::Used),
                    ("48h", UsernameLabelState::Used),
                    ("hyperbolic", UsernameLabelState::Ignored),
                ],
                expected_cfg: Some(FirewallUserConfig {
                    min_package_age: Some(Duration::from_hours(48)),
                }),
            },
            TestCase {
                description: "invalid min pkg-age: missing value (duration): min_pkg_age",
                io: &[
                    ("foo", UsernameLabelState::Ignored),
                    ("min_pkg_age", UsernameLabelState::Used),
                ],
                expected_cfg: None,
            },
            TestCase {
                description: "invalid min pkg-age: invalid value (duration): foo-min_pkg_age-bar",
                io: &[
                    ("foo", UsernameLabelState::Ignored),
                    ("min_pkg_age", UsernameLabelState::Used),
                    ("bar", UsernameLabelState::Abort),
                ],
                expected_cfg: None,
            },
        ] {
            let mut parser = FirewallUserConfigParser::default();

            for (label, expected_state) in test_case.io {
                let state = parser.parse_label(label);
                assert_eq!(*expected_state, state, "case: {}", test_case.description);
            }

            if test_case
                .io
                .last()
                .map(|s| s.1 == UsernameLabelState::Abort)
                .unwrap_or_default()
            {
                continue;
            }

            let mut ext = Extensions::new();
            let Ok(()) = parser.build(&mut ext);

            let maybe_cfg: Option<FirewallUserConfig> = ext.get().cloned();
            assert_eq!(
                test_case.expected_cfg, maybe_cfg,
                "case: {}",
                test_case.description
            );
        }
    }
}
