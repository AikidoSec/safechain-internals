use crate::package::version::PragmaticSemver;

use super::*;

#[test]
fn test_is_extension_install_asset_path() {
    // .vsix files should be blocked
    assert!(RuleVSCode::is_extension_install_asset_path(
        "/files/ms-python/python/1.0.0/whatever.vsix"
    ));
    assert!(RuleVSCode::is_extension_install_asset_path(
        "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
    ));
    assert!(RuleVSCode::is_extension_install_asset_path(
        "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage/"
    ));
    assert!(RuleVSCode::is_extension_install_asset_path(
        "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/vspackage"
    ));
    assert!(RuleVSCode::is_extension_install_asset_path(
        "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/vspackage/"
    ));

    // Manifest and signature files should NOT be blocked (they're just metadata)
    assert!(!RuleVSCode::is_extension_install_asset_path(
        "/_apis/public/gallery/publishers/ms-python/vsextensions/python/1.0.0/assetbyname/Microsoft.VisualStudio.Code.Manifest"
    ));
    assert!(!RuleVSCode::is_extension_install_asset_path(
        "/extensions/ms-python/python/1.0.0/Microsoft.VisualStudio.Services.VsixSignature"
    ));

    assert!(!RuleVSCode::is_extension_install_asset_path(
        "/extensions/ms-python/python/whatever"
    ));
}

#[test]
fn test_is_metadata_request_path() {
    assert!(RuleVSCode::is_metadata_request_path(
        "/_apis/public/gallery/extensionquery"
    ));
    assert!(RuleVSCode::is_metadata_request_path(
        "_ApIs/PuBlIc/GaLlErY/ExTeNsIoNqUeRy"
    ));

    assert!(!RuleVSCode::is_metadata_request_path(
        "/extensions/ms-python/python/1.0.0/Microsoft.VisualStudio.Code.Manifest"
    ));
    assert!(!RuleVSCode::is_metadata_request_path(
        "/files/ms-python/python/1.0.0/ms-python.python-1.0.0.vsix"
    ));
}

#[test]
fn test_parse_extension_id_from_path() {
    let test_cases = vec![
        (
            "/files/ms-python/python/2024.22.0/ms-python.python-2024.22.0.vsix",
            Some("ms-python.python"),
        ),
        (
            "/FiLeS/ms-python/python/2024.22.0/ms-python.python-2024.22.0.vsix",
            Some("ms-python.python"),
        ),
        (
            "files/ms-python/python/2024.22.0/ms-python.python-2024.22.0.vsix",
            Some("ms-python.python"),
        ),
        (
            "/_apis/public/gallery/publisher/ms-python/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("ms-python.python"),
        ),
        (
            "/_ApIs/PuBlIc/GaLlErY/Publisher/ms-python/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("ms-python.python"),
        ),
        (
            "/_apis/public/gallery/publisher/AddictedGuys/extension/vscode-har-explorer/1.0.0/assetbyname/Microsoft.VisualStudio.Code.Manifest",
            Some("addictedguys.vscode-har-explorer"),
        ),
        (
            "/_apis/public/gallery/publishers/ms-python/vsextensions/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Code.Manifest",
            Some("ms-python.python"),
        ),
        (
            "/_APIs/Public/Gallery/Publishers/ms-python/VSextensions/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Code.Manifest",
            Some("ms-python.python"),
        ),
        (
            "/_apis/public/gallery/publishers/MattFoulks/extensions/har-analyzer/0.0.11/vspackage",
            Some("mattfoulks.har-analyzer"),
        ),
        (
            "/extensions/ms-python/python/2024.22.0/Microsoft.VisualStudio.Services.VsixSignature",
            Some("ms-python.python"),
        ),
        (
            "/ExTeNsIoNs/ms-python/python/2024.22.0/Microsoft.VisualStudio.Services.VsixSignature",
            Some("ms-python.python"),
        ),
        ("/extensions/ms-python/python", Some("ms-python.python")),
        ("/files/ms-python/python", None),
        (
            "/_apis/public/gallery/publishers/ms-python/notvsextensions/python/1.0.0",
            None,
        ),
        ("/something/else", None),
    ];

    for (input, expected) in test_cases {
        let parsed = RuleVSCode::parse_extension_id_from_path(input).map(|v| v.extension_id);
        assert_eq!(
            parsed,
            expected.map(VSCodePackageName::from),
            "input: '{input}'"
        );
    }
}

#[test]
fn test_parse_extension_id_from_path_lowercased() {
    let test_cases = vec![
        (
            "/files/AddictedGuys/VSCode-HAR-Explorer/1.0.0/extension.vsix",
            Some("addictedguys.vscode-har-explorer"),
        ),
        (
            "/extensions/MS-Python/Python/2024.22.0/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("ms-python.python"),
        ),
        (
            "/_apis/public/gallery/publisher/Microsoft/VSCode/1.0.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("microsoft.vscode"),
        ),
        (
            "/_apis/public/gallery/publishers/GitHub/vsextensions/Copilot/1.0.0/assetbyname/Microsoft.VisualStudio.Code.Manifest",
            Some("github.copilot"),
        ),
    ];

    for (input, expected) in test_cases {
        let parsed = RuleVSCode::parse_extension_id_from_path(input).map(|v| v.extension_id);
        assert_eq!(
            parsed,
            expected.map(VSCodePackageName::from),
            "Failed to parse path: {}",
            input
        );
    }
}

#[test]
fn test_parse_extension_id_version_captured() {
    struct TestCase {
        // keeps the original inline comment intent
        comment: &'static str,
        path: &'static str,
        expected_extension_id: VSCodePackageName,
        expected_version: Option<PackageVersion>,
    }

    let cases = [
        TestCase {
            comment: "files/<pub>/<ext>/<version>/...",
            path: "/files/ms-python/python/2024.22.0/ms-python.python-2024.22.0.vsix",
            expected_extension_id: VSCodePackageName::from("ms-python.python"),
            expected_version: Some(PackageVersion::Semver(PragmaticSemver::new_semver(
                2024, 22, 0,
            ))),
        },
        TestCase {
            comment: "extensions/<pub>/<ext>/<version>/...",
            path: "/extensions/ms-python/python/2024.22.0/Microsoft.VisualStudio.Services.VsixSignature",
            expected_extension_id: VSCodePackageName::from("ms-python.python"),
            expected_version: Some(PackageVersion::Semver(PragmaticSemver::new_semver(
                2024, 22, 0,
            ))),
        },
        TestCase {
            comment: "extensions/<pub>/<ext> (no version)",
            path: "/extensions/ms-python/python",
            expected_extension_id: VSCodePackageName::from("ms-python.python"),
            expected_version: None,
        },
        TestCase {
            comment: "_apis/public/gallery/publishers/<pub>/vsextensions/<ext>/<version>/...",
            path: "/_apis/public/gallery/publishers/ms-python/vsextensions/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
            expected_extension_id: VSCodePackageName::from("ms-python.python"),
            expected_version: Some(PackageVersion::Semver(PragmaticSemver::new_semver(
                2024, 22, 0,
            ))),
        },
        TestCase {
            comment: "_apis/public/gallery/publisher/<pub>/<ext>/<version>/...",
            path: "/_apis/public/gallery/publisher/ms-python/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
            expected_extension_id: VSCodePackageName::from("ms-python.python"),
            expected_version: Some(PackageVersion::Semver(PragmaticSemver::new_semver(
                2024, 22, 0,
            ))),
        },
        TestCase {
            comment: "_apis/public/gallery/publisher/<pub>/extension/<ext>/<version>/...",
            path: "/_apis/public/gallery/publisher/AddictedGuys/extension/vscode-har-explorer/1.0.0/assetbyname/Microsoft.VisualStudio.Code.Manifest",
            expected_extension_id: VSCodePackageName::from("addictedguys.vscode-har-explorer"),
            expected_version: Some(PackageVersion::Semver(PragmaticSemver::new_semver(1, 0, 0))),
        },
        TestCase {
            comment: "version lowercased",
            path: "/files/Publisher/Extension/1.0.0-BETA/extension.vsix",
            expected_extension_id: VSCodePackageName::from("publisher.extension"),
            expected_version: Some(PackageVersion::Semver(
                PragmaticSemver::parse("1.0.0-beta").unwrap(),
            )),
        },
    ];

    for case in cases {
        let parsed = RuleVSCode::parse_extension_id_from_path(case.path)
            .unwrap_or_else(|| panic!("{} failed for path {}", case.comment, case.path));

        assert_eq!(
            parsed.extension_id, case.expected_extension_id,
            "{}: extension_id mismatch for path {}",
            case.comment, case.path
        );
        assert_eq!(
            parsed.version, case.expected_version,
            "{}: version mismatch for path {}",
            case.comment, case.path
        );
    }
}
