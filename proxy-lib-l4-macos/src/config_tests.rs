use super::*;

fn parse(input: Option<&[u8]>) -> Result<ProxyConfig, BoxError> {
    ProxyConfig::from_opaque_config(input)
}

#[test]
fn deserializes_valid_configs() {
    let cases = [
        ("none uses defaults", None, ProxyConfig::default()),
        (
            "empty bytes uses defaults",
            Some(&[] as &[u8]),
            ProxyConfig::default(),
        ),
        (
            "empty json uses defaults",
            Some(br#"{}"# as &[u8]),
            ProxyConfig::default(),
        ),
        (
            "custom aikido url",
            Some(br#"{"aikido_url":"https://example.aikido.dev"}"# as &[u8]),
            ProxyConfig {
                aikido_url: Uri::from_static("https://example.aikido.dev"),
                ..ProxyConfig::default()
            },
        ),
        (
            "full config",
            Some(
                br#"{
                        "peek_duration_s": 12.5,
                        "reporting_endpoint": "https://collector.aikido.dev/report",
                        "aikido_url": "https://app.aikido.dev"
                    }"# as &[u8],
            ),
            ProxyConfig {
                peek_duration_s: 12.5,
                reporting_endpoint: Some(Uri::from_static("https://collector.aikido.dev/report")),
                aikido_url: Uri::from_static("https://app.aikido.dev"),
                ..ProxyConfig::default()
            },
        ),
        (
            "null optional uri",
            Some(
                br#"{
                        "reporting_endpoint": null,
                        "aikido_url": "https://app.aikido.dev"
                    }"# as &[u8],
            ),
            ProxyConfig {
                aikido_url: Uri::from_static("https://app.aikido.dev"),
                ..ProxyConfig::default()
            },
        ),
    ];

    for (name, input, expected) in cases {
        let actual =
            parse(input).unwrap_or_else(|err| panic!("case {name:?} failed to deserialize: {err}"));
        assert_eq!(actual, expected, "case: {name}");
    }
}

#[test]
fn rejects_invalid_configs() {
    let cases = [
        (
            "invalid reporting endpoint",
            br#"{
                    "reporting_endpoint": "not a uri",
                    "aikido_url": "https://app.aikido.dev"
                }"# as &[u8],
            &["uri"][..],
        ),
        (
            "invalid aikido url",
            br#"{
                    "aikido_url": "definitely not a uri"
                }"# as &[u8],
            &["uri"][..],
        ),
        (
            "invalid json gets context",
            br#"{"aikido_url":"https://app.aikido.dev""# as &[u8],
            &["decode transparent proxy engine config json"][..],
        ),
    ];

    for (name, input, needles) in cases {
        let err = parse(Some(input)).expect_err(name);
        let msg = err.to_string().to_lowercase();

        for needle in needles {
            assert!(
                msg.contains(needle),
                "case {name:?}: expected error to contain {needle:?}, got {msg:?}"
            );
        }
    }
}
