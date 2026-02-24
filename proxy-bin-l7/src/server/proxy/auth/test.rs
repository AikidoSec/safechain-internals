use serde::{Serialize, Serializer};

use super::*;

impl Serialize for FirewallUserConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Debug, Serialize)]
        struct T {
            min_pkg_age: Option<String>,
        }

        T {
            min_pkg_age: self
                .min_package_age
                .map(|d| humantime::format_duration(d).to_string()),
        }
        .serialize(serializer)
    }
}

#[test]
#[tracing_test::traced_test]
fn test_parse_humantime_str() {
    for (input, expected_output) in [
        ("", None),
        ("5h", Some(Duration::from_hours(5))),
        ("3m", Some(Duration::from_mins(3))),
        (
            "5h_30m",
            Some(Duration::from_hours(5) + Duration::from_mins(30)),
        ),
        (
            "5h 30m",
            Some(Duration::from_hours(5) + Duration::from_mins(30)),
        ),
        ("5h-30m", None),
        ("foo", None),
    ] {
        match (parse_humantime_str(input), expected_output) {
            (Ok(output), Some(expected_output)) => {
                assert_eq!(expected_output, output, "input: '{input}'")
            }
            (Err(_), None) => (),
            (Ok(output), None) => panic!("unexpected output '{output:?}' (input: '{input}'"),
            (Err(err), Some(expected_output)) => panic!(
                "unexpected error '{err:?}', expected output: {expected_output:?} (input: '{input}')"
            ),
        }
    }
}

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
