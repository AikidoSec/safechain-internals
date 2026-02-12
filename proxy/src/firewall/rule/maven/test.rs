use crate::firewall::version::PragmaticSemver;

use super::*;

#[test]
fn test_parse_artifact_happy_paths_table() {
    fn assert_parsed(domain: &str, path: &str, expected_fqn: &str, expected_version: &str) {
        let artifact = RuleMaven::parse_artifact_from_path_for_domain(path, domain)
            .unwrap_or_else(|| panic!("expected artifact to parse: domain={domain} path={path}"));

        assert_eq!(artifact.fully_qualified_name.as_str(), expected_fqn);
        assert_eq!(
            artifact.version,
            PragmaticSemver::parse(expected_version).unwrap()
        );
    }

    let cases: [(&str, &str, &str, &str); 8] = [
        (
            "repo.maven.apache.org",
            "org/apache/maven/maven/2.0/maven-2.0.jar",
            "org.apache.maven:maven",
            "2.0",
        ),
        (
            "repo.maven.apache.org",
            "maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
            "org.apache.commons:commons-lang3",
            "3.14.0",
        ),
        (
            "repository.apache.org",
            "content/repositories/releases/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
            "org.apache.commons:commons-lang3",
            "3.14.0",
        ),
        (
            "maven.google.com",
            "org/example/lib/1.0.0/lib-1.0.0-sources.jar",
            "org.example:lib",
            "1.0.0",
        ),
        (
            "repo.maven.apache.org",
            "org/example/webapp/3.0.0/webapp-3.0.0.war",
            "org.example:webapp",
            "3.0.0",
        ),
        (
            "repo.maven.apache.org",
            "com/google/android/material/1.8.0/material-1.8.0.aar",
            "com.google.android:material",
            "1.8.0",
        ),
        (
            "repo.maven.apache.org",
            "org/example/lib/1.0.0-SNAPSHOT/lib-1.0.0-SNAPSHOT.jar",
            "org.example:lib",
            "1.0.0-SNAPSHOT",
        ),
        (
            "repo1.maven.org",
            "maven2/org/hdrhistogram/HdrHistogram/2.1.12/HdrHistogram-2.1.12.jar",
            "org.hdrhistogram:hdrhistogram",
            "2.1.12",
        ),
    ];

    for (domain, path, expected_fqn, expected_version) in cases {
        assert_parsed(domain, path, expected_fqn, expected_version);
    }
}

#[test]
fn test_parse_artifact_for_repository_apache_all_known_prefixes() {
    let cases: [(&str, &str); 3] = [
        (
            "content/repositories/releases/org/example/lib/1.0.0/lib-1.0.0.jar",
            "1.0.0",
        ),
        (
            "content/repositories/snapshots/org/example/lib/1.0.1-SNAPSHOT/lib-1.0.1-SNAPSHOT.jar",
            "1.0.1-SNAPSHOT",
        ),
        (
            "content/groups/public/org/example/lib/2.0.0/lib-2.0.0.jar",
            "2.0.0",
        ),
    ];

    for (path, expected_version) in cases {
        let artifact =
            RuleMaven::parse_artifact_from_path_for_domain(path, "repository.apache.org")
                .unwrap_or_else(|| panic!("expected apache repository path to parse: {path}"));
        assert_eq!(artifact.fully_qualified_name.as_str(), "org.example:lib");
        assert_eq!(
            artifact.version,
            PragmaticSemver::parse(expected_version).unwrap()
        );
    }
}

#[test]
fn test_parse_artifact_handles_leading_slash_paths() {
    let artifact = RuleMaven::parse_artifact_from_path_for_domain(
        "/maven2/org/example/lib/1.2.3/lib-1.2.3.jar",
        "repo1.maven.org",
    )
    .unwrap_or_else(|| panic!("expected leading-slash path to parse"));

    assert_eq!(artifact.fully_qualified_name.as_str(), "org.example:lib");
    assert_eq!(artifact.version, PragmaticSemver::parse("1.2.3").unwrap());
}

#[test]
fn test_strip_path_prefix_requires_segment_boundary() {
    assert_eq!(
        RuleMaven::strip_path_prefix("maven2/org/apache", "maven2"),
        Some("org/apache")
    );
    assert_eq!(RuleMaven::strip_path_prefix("maven2", "maven2"), Some(""));
    assert_eq!(
        RuleMaven::strip_path_prefix("maven2org/apache", "maven2"),
        None
    );
}

#[test]
fn test_reject_non_artifacts_table() {
    let rejects: [&str; 11] = [
        "org/example/lib/1.0.0/lib-1.0.0",
        "org/example/lib",
        "org/springframework/spring-core/maven-metadata.xml",
        "org/example/lib/1.0.0/lib-1.0.0.jar.sha1",
        "org/example/lib/1.0.0/lib-1.0.0.jar.md5",
        "org/example/lib/1.0.0/lib-1.0.0.jar.sha256",
        "org/example/lib/1.0.0/lib-1.0.0.jar.asc",
        "org/example/lib/1.0.0/different-name-2.0.0.jar",
        "org/example/lib/1.0.0/lib-2.0.0.jar",
        "org/example/lib/1.0.0/lib-1.0.0extra.jar",
        "org/example/lib/1.0.0/lib-1.0.0.pom",
    ];

    for path in rejects {
        assert!(
            RuleMaven::parse_artifact_from_path(path).is_none(),
            "expected rejection for path: {path}"
        );
    }
}

#[test]
fn test_parse_real_world_full_urls_smoke() {
    let urls: [&str; 6] = [
        "https://repo.maven.apache.org/maven2/org/apache/httpcomponents/httpclient/4.5.13/httpclient-4.5.13.jar",
        "https://repo1.maven.org/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar",
        "https://repo1.maven.org/maven2/org/hibernate/orm/hibernate-core/6.4.2.Final/hibernate-core-6.4.2.Final.jar",
        "https://repo1.maven.org/maven2/io/netty/netty-transport-native-epoll/4.1.106.Final/netty-transport-native-epoll-4.1.106.Final-linux-x86_64.jar",
        "https://repo.maven.apache.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar",
        "https://repo1.maven.org/maven2/org/hdrhistogram/HdrHistogram/2.1.12/HdrHistogram-2.1.12.jar",
    ];

    for url in urls {
        let without_scheme = url
            .strip_prefix("https://")
            .unwrap_or_else(|| panic!("expected https URL: {url}"));
        let (domain, path) = without_scheme
            .split_once('/')
            .unwrap_or_else(|| panic!("expected URL with path: {url}"));

        let artifact = RuleMaven::parse_artifact_from_path_for_domain(path, domain)
            .unwrap_or_else(|| panic!("expected maven .jar to be parsed: {url}"));

        // Ensure we didn't accidentally treat the repository prefix as part of the groupId.
        assert!(!artifact.fully_qualified_name.as_str().contains("maven2."));
    }
}
