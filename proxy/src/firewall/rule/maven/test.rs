use crate::firewall::version::PragmaticSemver;

use super::*;

#[test]
fn test_parse_simple_artifact() {
    let path = "org/apache/maven/maven/2.0/maven-2.0.jar";
    let artifact = parse_artifact_from_path_for_domain(path, "repo.maven.apache.org");

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(
        artifact.fully_qualified_name.as_str(),
        "org.apache.maven:maven"
    );
    assert_eq!(artifact.version, PragmaticSemver::new_two_components(2, 0));
}

#[test]
fn test_parse_maven_central_with_maven2_prefix() {
    let path = "maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar";
    let artifact = parse_artifact_from_path_for_domain(path, "repo.maven.apache.org");

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(
        artifact.fully_qualified_name.as_str(),
        "org.apache.commons:commons-lang3"
    );
    assert_eq!(artifact.version, PragmaticSemver::new_semver(3, 14, 0));
}

#[test]
fn test_parse_apache_repo_with_content_releases_prefix() {
    let path = "content/repositories/releases/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar";
    let artifact = parse_artifact_from_path_for_domain(path, "repository.apache.org");

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(
        artifact.fully_qualified_name.as_str(),
        "org.apache.commons:commons-lang3"
    );
    assert_eq!(artifact.version, PragmaticSemver::new_semver(3, 14, 0));
}

#[test]
fn test_parse_deep_group_id() {
    let path = "com/example/lib/module/1.2.3/module-1.2.3.jar";
    let artifact = parse_artifact_from_path_for_domain(path, "repo.spring.io");

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(
        artifact.fully_qualified_name.as_str(),
        "com.example.lib:module"
    );
    assert_eq!(artifact.version, PragmaticSemver::new_semver(1, 2, 3));
}

#[test]
fn test_parse_jar_with_classifier_old() {
    let path = "org/example/lib/1.0.0/lib-1.0.0-sources.jar";
    let artifact = parse_artifact_from_path_for_domain(path, "maven.google.com");

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.example:lib");
    assert_eq!(artifact.version, PragmaticSemver::new_semver(1, 0, 0));
}

#[test]
fn test_reject_path_without_file_extension() {
    // File without extension should be rejected
    let path = "org/example/lib/1.0.0/lib-1.0.0";
    let artifact = parse_artifact_from_path_for_domain(path, "repo.maven.apache.org");
    assert!(artifact.is_none(), "Should reject files without extension");
}

#[test]
fn test_parse_invalid_path_too_short() {
    let path = "org/example/lib";
    let artifact = parse_artifact_from_path_for_domain(path, "repo.maven.apache.org");
    assert!(artifact.is_none());
}

#[test]
fn test_parse_deep_group_path() {
    let path = "org/fasterxml/jackson/core/jackson-databind/2.20.1/jackson-databind-2.20.1.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(
        artifact.fully_qualified_name.as_str(),
        "org.fasterxml.jackson.core:jackson-databind"
    );
    assert_eq!(artifact.version, PragmaticSemver::new_semver(2, 20, 1));
}

#[test]
fn test_parse_artifact_with_sources_classifier() {
    let path = "org/example/lib/1.0.0/lib-1.0.0-sources.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.example:lib");
    assert_eq!(artifact.version, PragmaticSemver::new_semver(1, 0, 0));
}

#[test]
fn test_parse_artifact_with_javadoc_classifier() {
    let path = "org/springframework/spring-core/6.2.1/spring-core-6.2.1-javadoc.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(
        artifact.fully_qualified_name.as_str(),
        "org.springframework:spring-core"
    );
    assert_eq!(artifact.version, PragmaticSemver::new_semver(6, 2, 1));
}

#[test]
fn test_parse_artifact_with_tests_classifier() {
    let path = "com/example/mylib/2.5.0/mylib-2.5.0-tests.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "com.example:mylib");
    assert_eq!(artifact.version, PragmaticSemver::new_semver(2, 5, 0));
}

#[test]
fn test_reject_metadata_xml() {
    let path = "org/springframework/spring-core/maven-metadata.xml";
    let artifact = parse_artifact_from_path(path);
    assert!(artifact.is_none(), "Should reject maven-metadata.xml files");
}

#[test]
fn test_reject_sha1_checksum() {
    let path = "org/example/lib/1.0.0/lib-1.0.0.jar.sha1";
    let artifact = parse_artifact_from_path(path);
    assert!(artifact.is_none(), "Should reject .sha1 checksum files");
}

#[test]
fn test_reject_md5_checksum() {
    let path = "org/example/lib/1.0.0/lib-1.0.0.jar.md5";
    let artifact = parse_artifact_from_path(path);
    assert!(artifact.is_none(), "Should reject .md5 checksum files");
}

#[test]
fn test_reject_sha256_checksum() {
    let path = "org/example/lib/1.0.0/lib-1.0.0.jar.sha256";
    let artifact = parse_artifact_from_path(path);
    assert!(artifact.is_none(), "Should reject .sha256 checksum files");
}

#[test]
fn test_reject_asc_signature() {
    let path = "org/example/lib/1.0.0/lib-1.0.0.jar.asc";
    let artifact = parse_artifact_from_path(path);
    assert!(artifact.is_none(), "Should reject .asc signature files");
}

#[test]
fn test_reject_mismatched_filename() {
    // Filename doesn't match the expected artifactId-version pattern
    let path = "org/example/lib/1.0.0/different-name-2.0.0.jar";
    let artifact = parse_artifact_from_path(path);
    assert!(
        artifact.is_none(),
        "Should reject filename that doesn't match artifactId-version pattern"
    );
}

#[test]
fn test_reject_invalid_version_in_filename() {
    // Version in path doesn't match version in filename
    let path = "org/example/lib/1.0.0/lib-2.0.0.jar";
    let artifact = parse_artifact_from_path(path);
    assert!(
        artifact.is_none(),
        "Should reject when filename version doesn't match path version"
    );
}

#[test]
fn test_parse_war_file() {
    let path = "org/example/webapp/3.0.0/webapp-3.0.0.war";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.example:webapp");
    assert_eq!(artifact.version, PragmaticSemver::new_semver(3, 0, 0));
}

#[test]
fn test_parse_aar_file() {
    let path = "com/google/android/material/1.8.0/material-1.8.0.aar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(
        artifact.fully_qualified_name.as_str(),
        "com.google.android:material"
    );
    assert_eq!(artifact.version, PragmaticSemver::new_semver(1, 8, 0));
}

#[test]
fn test_parse_snapshot_version() {
    // Maven snapshots like 1.0.0-SNAPSHOT
    let path = "org/example/lib/1.0.0-SNAPSHOT/lib-1.0.0-SNAPSHOT.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.example:lib");
    assert_eq!(
        artifact.version,
        PragmaticSemver::new_semver(1, 0, 0).with_pre("SNAPSHOT")
    );
}

#[test]
fn test_parse_jar_urls_seen_in_maven_debug_log() {
    // URL → (groupId, artifactId, version)
    let cases: [(&str, &str, &str, &str); 20] = [
        (
            "https://repo.maven.apache.org/maven2/commons-codec/commons-codec/1.16.1/commons-codec-1.16.1.jar",
            "commons-codec",
            "commons-codec",
            "1.16.1",
        ),
        (
            "https://repo.maven.apache.org/maven2/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar",
            "commons-collections",
            "commons-collections",
            "3.2.2",
        ),
        (
            "https://repo.maven.apache.org/maven2/commons-io/commons-io/2.15.1/commons-io-2.15.1.jar",
            "commons-io",
            "commons-io",
            "2.15.1",
        ),
        (
            "https://repo.maven.apache.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar",
            "commons-logging",
            "commons-logging",
            "1.2",
        ),
        (
            "https://repo.maven.apache.org/maven2/org/apache/httpcomponents/httpclient/4.5.13/httpclient-4.5.13.jar",
            "org.apache.httpcomponents",
            "httpclient",
            "4.5.13",
        ),
        (
            "https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/1.4.14/logback-classic-1.4.14.jar",
            "ch.qos.logback",
            "logback-classic",
            "1.4.14",
        ),
        (
            "https://repo1.maven.org/maven2/ch/qos/logback/logback-core/1.4.14/logback-core-1.4.14.jar",
            "ch.qos.logback",
            "logback-core",
            "1.4.14",
        ),
        (
            "https://repo1.maven.org/maven2/com/fasterxml/classmate/1.5.1/classmate-1.5.1.jar",
            "com.fasterxml",
            "classmate",
            "1.5.1",
        ),
        (
            "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.16.1/jackson-annotations-2.16.1.jar",
            "com.fasterxml.jackson.core",
            "jackson-annotations",
            "2.16.1",
        ),
        (
            "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.16.1/jackson-core-2.16.1.jar",
            "com.fasterxml.jackson.core",
            "jackson-core",
            "2.16.1",
        ),
        (
            "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.16.1/jackson-databind-2.16.1.jar",
            "com.fasterxml.jackson.core",
            "jackson-databind",
            "2.16.1",
        ),
        (
            "https://repo1.maven.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/2.16.0/jackson-dataformat-yaml-2.16.0.jar",
            "com.fasterxml.jackson.dataformat",
            "jackson-dataformat-yaml",
            "2.16.0",
        ),
        (
            "https://repo1.maven.org/maven2/com/github/luben/zstd-jni/1.5.5-1/zstd-jni-1.5.5-1.jar",
            "com.github.luben",
            "zstd-jni",
            "1.5.5-1",
        ),
        (
            "https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar",
            "com.google.code.gson",
            "gson",
            "2.10.1",
        ),
        (
            "https://repo1.maven.org/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar",
            "com.google.guava",
            "guava",
            "33.0.0-jre",
        ),
        (
            "https://repo1.maven.org/maven2/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar",
            "com.google.guava",
            "listenablefuture",
            "9999.0-empty-to-avoid-conflict-with-guava",
        ),
        (
            "https://repo1.maven.org/maven2/org/hdrhistogram/HdrHistogram/2.1.12/HdrHistogram-2.1.12.jar",
            "org.hdrhistogram",
            "hdrhistogram",
            "2.1.12",
        ),
        (
            "https://repo1.maven.org/maven2/org/hibernate/orm/hibernate-core/6.4.2.Final/hibernate-core-6.4.2.Final.jar",
            "org.hibernate.orm",
            "hibernate-core",
            "6.4.2.Final",
        ),
        (
            "https://repo1.maven.org/maven2/io/netty/netty-codec-http/4.1.106.Final/netty-codec-http-4.1.106.Final.jar",
            "io.netty",
            "netty-codec-http",
            "4.1.106.Final",
        ),
        (
            "https://repo1.maven.org/maven2/io/netty/netty-transport-native-epoll/4.1.106.Final/netty-transport-native-epoll-4.1.106.Final-linux-x86_64.jar",
            "io.netty",
            "netty-transport-native-epoll",
            "4.1.106.Final",
        ),
    ];

    for (url, expected_group_id, expected_artifact_id, expected_version) in cases {
        let without_scheme = url
            .strip_prefix("https://")
            .unwrap_or_else(|| panic!("expected https URL: {url}"));
        let (domain, path) = without_scheme
            .split_once('/')
            .unwrap_or_else(|| panic!("expected URL with path: {url}"));

        let artifact = parse_artifact_from_path_for_domain(path, domain)
            .unwrap_or_else(|| panic!("expected maven .jar to be parsed: {url}"));

        let expected_fqn = format!("{expected_group_id}:{expected_artifact_id}");
        assert_eq!(
            artifact.fully_qualified_name.as_str(),
            expected_fqn.as_str()
        );
        assert_eq!(
            artifact.version,
            PragmaticSemver::parse(expected_version).unwrap()
        );

        // Ensure we didn't accidentally treat the repository prefix as part of the groupId.
        assert!(!artifact.fully_qualified_name.as_str().contains("maven2."));
    }
}
