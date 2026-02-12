use super::*;

#[tokio::test]
async fn test_parse_npm_package_from_path() {
    for (path, expected) in [
        (
            "lodash/-/lodash-4.17.21.tgz",
            Some(NpmPackage::new(
                "lodash",
                PragmaticSemver::new_semver(4, 17, 21),
            )),
        ),
        (
            "/lodash/-/lodash-4.17.21.tgz",
            Some(NpmPackage::new(
                "lodash",
                PragmaticSemver::new_semver(4, 17, 21),
            )),
        ),
        ("lodash/-/lodash-4.17.21", None),
        ("lodash", None),
        (
            "express/-/express-4.18.2.tgz",
            Some(NpmPackage::new(
                "express",
                PragmaticSemver::new_semver(4, 18, 2),
            )),
        ),
        (
            "safe-chain-test/-/safe-chain-test-1.0.0.tgz",
            Some(NpmPackage::new(
                "safe-chain-test",
                PragmaticSemver::new_semver(1, 0, 0),
            )),
        ),
        (
            "web-vitals/-/web-vitals-3.5.0.tgz",
            Some(NpmPackage::new(
                "web-vitals",
                PragmaticSemver::new_semver(3, 5, 0),
            )),
        ),
        (
            "safe-chain-test/-/safe-chain-test-0.0.1-security.tgz",
            Some(NpmPackage::new(
                "safe-chain-test",
                PragmaticSemver::new_semver(0, 0, 1).with_pre("security"),
            )),
        ),
        (
            "lodash/-/lodash-5.0.0-beta.1.tgz",
            Some(NpmPackage::new(
                "lodash",
                PragmaticSemver::new_semver(5, 0, 0).with_pre("beta.1"),
            )),
        ),
        (
            "react/-/react-18.3.0-canary-abc123.tgz",
            Some(NpmPackage::new(
                "react",
                PragmaticSemver::new_semver(18, 3, 0).with_pre("canary-abc123"),
            )),
        ),
        (
            "@babel/core/-/core-7.21.4.tgz",
            Some(NpmPackage::new(
                "@babel/core",
                PragmaticSemver::new_semver(7, 21, 4),
            )),
        ),
        (
            "@types/node/-/node-20.10.5.tgz",
            Some(NpmPackage::new(
                "@types/node",
                PragmaticSemver::new_semver(20, 10, 5),
            )),
        ),
        (
            "@angular/common/-/common-17.0.8.tgz",
            Some(NpmPackage::new(
                "@angular/common",
                PragmaticSemver::new_semver(17, 0, 8),
            )),
        ),
        (
            "@safe-chain/test-package/-/test-package-2.1.0.tgz",
            Some(NpmPackage::new(
                "@safe-chain/test-package",
                PragmaticSemver::new_semver(2, 1, 0),
            )),
        ),
        (
            "@aws-sdk/client-s3/-/client-s3-3.465.0.tgz",
            Some(NpmPackage::new(
                "@aws-sdk/client-s3",
                PragmaticSemver::new_semver(3, 465, 0),
            )),
        ),
        (
            "@babel/core/-/core-8.0.0-alpha.1.tgz",
            Some(NpmPackage::new(
                "@babel/core",
                PragmaticSemver::new_semver(8, 0, 0).with_pre("alpha.1"),
            )),
        ),
        (
            "@safe-chain/security-test/-/security-test-1.0.0-security.tgz",
            Some(NpmPackage::new(
                "@safe-chain/security-test",
                PragmaticSemver::new_semver(1, 0, 0).with_pre("security"),
            )),
        ),
    ] {
        let result = parse_package_from_path(path);

        match (result, expected) {
            (Some(actual_package), Some(expected_package)) => {
                assert_eq!(
                    expected_package.fully_qualified_name,
                    actual_package.fully_qualified_name
                );
                assert_eq!(expected_package.version, actual_package.version);
            }
            (None, None) => {}
            (Some(actual_package), None) => {
                unreachable!(
                    "No package expected, but got '{}'",
                    actual_package.fully_qualified_name
                );
            }
            (None, Some(expected_package)) => {
                unreachable!(
                    "Expected '{}', but got None",
                    expected_package.fully_qualified_name
                );
            }
        }
    }
}
