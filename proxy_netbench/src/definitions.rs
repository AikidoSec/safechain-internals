use rama::net::address::Domain;

// used as a pseudo-domain for gathering reports
pub const FAKE_AIKIDO_REPORTER_DOMAIN: Domain =
    Domain::from_static("reporter.fake-aikido.internal");
