use crate::firewall::version::PragmaticSemver;

use super::*;

#[test]
fn test_parse_simple_artifact() {
    let path = "org/apache/maven/maven/2.0/maven-2.0.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.apache.maven:maven");
    assert_eq!(artifact.version, PragmaticSemver::new_two_components(2, 0));
}

#[test]
fn test_parse_deep_group_id() {
    let path = "com/example/lib/module/1.2.3/module-1.2.3.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "com.example.lib:module");
    assert_eq!(artifact.version, PragmaticSemver::new_semver(1, 2, 3));
}

#[test]
fn test_parse_pom_file() {
    // POM files are artifacts and should be parsed and checked against malware list
    let path = "org/mvnpm/carbon-components/11.66.1/carbon-components-11.66.1.pom";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.mvnpm:carbon-components");
    assert_eq!(artifact.version, PragmaticSemver::new_semver(11, 66, 1));
}

#[test]
fn test_parse_jar_with_classifier_old() {
    let path = "org/example/lib/1.0.0/lib-1.0.0-sources.jar";
    let artifact = parse_artifact_from_path(path);

    assert!(artifact.is_some());
    let artifact = artifact.unwrap();
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.example:lib");
    assert_eq!(artifact.version, PragmaticSemver::new_semver(1, 0, 0));
}

#[test]
fn test_reject_path_without_file_extension() {
    // File without extension should be rejected
    let path = "org/example/lib/1.0.0/lib-1.0.0";
    let artifact = parse_artifact_from_path(path);
    assert!(artifact.is_none(), "Should reject files without extension");
}

#[test]
fn test_parse_invalid_path_too_short() {
    let path = "org/example/lib";
    let artifact = parse_artifact_from_path(path);
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
    assert_eq!(artifact.fully_qualified_name.as_str(), "org.springframework:spring-core");
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
    assert!(artifact.is_none(), "Should reject filename that doesn't match artifactId-version pattern");
}

#[test]
fn test_reject_invalid_version_in_filename() {
    // Version in path doesn't match version in filename
    let path = "org/example/lib/1.0.0/lib-2.0.0.jar";
    let artifact = parse_artifact_from_path(path);
    assert!(artifact.is_none(), "Should reject when filename version doesn't match path version");
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
    assert_eq!(artifact.fully_qualified_name.as_str(), "com.google.android:material");
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
    assert_eq!(artifact.version, PragmaticSemver::new_semver(1, 0, 0).with_pre("SNAPSHOT"));
}
