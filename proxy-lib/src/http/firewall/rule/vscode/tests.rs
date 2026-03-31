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
        assert_eq!(parsed.as_deref(), expected, "input: '{input}'");
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
            parsed.as_deref(),
            expected,
            "Failed to parse path: {}",
            input
        );
    }
}

#[test]
fn test_parse_extension_id_version_captured() {
    // files/<pub>/<ext>/<version>/...
    let parsed = RuleVSCode::parse_extension_id_from_path(
        "/files/ms-python/python/2024.22.0/ms-python.python-2024.22.0.vsix",
    )
    .unwrap();
    assert_eq!(parsed.extension_id, "ms-python.python");
    assert_eq!(parsed.version.as_deref(), Some("2024.22.0"));

    // extensions/<pub>/<ext>/<version>/...
    let parsed = RuleVSCode::parse_extension_id_from_path(
        "/extensions/ms-python/python/2024.22.0/Microsoft.VisualStudio.Services.VsixSignature",
    )
    .unwrap();
    assert_eq!(parsed.extension_id, "ms-python.python");
    assert_eq!(parsed.version.as_deref(), Some("2024.22.0"));

    // extensions/<pub>/<ext> (no version)
    let parsed = RuleVSCode::parse_extension_id_from_path("/extensions/ms-python/python").unwrap();
    assert_eq!(parsed.extension_id, "ms-python.python");
    assert_eq!(parsed.version, None);

    // _apis/public/gallery/publishers/<pub>/vsextensions/<ext>/<version>/...
    let parsed = RuleVSCode::parse_extension_id_from_path(
        "/_apis/public/gallery/publishers/ms-python/vsextensions/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
    )
    .unwrap();
    assert_eq!(parsed.extension_id, "ms-python.python");
    assert_eq!(parsed.version.as_deref(), Some("2024.22.0"));

    // _apis/public/gallery/publisher/<pub>/<ext>/<version>/...
    let parsed = RuleVSCode::parse_extension_id_from_path(
        "/_apis/public/gallery/publisher/ms-python/python/2024.22.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
    )
    .unwrap();
    assert_eq!(parsed.extension_id, "ms-python.python");
    assert_eq!(parsed.version.as_deref(), Some("2024.22.0"));

    // _apis/public/gallery/publisher/<pub>/extension/<ext>/<version>/...
    let parsed = RuleVSCode::parse_extension_id_from_path(
        "/_apis/public/gallery/publisher/AddictedGuys/extension/vscode-har-explorer/1.0.0/assetbyname/Microsoft.VisualStudio.Code.Manifest",
    )
    .unwrap();
    assert_eq!(parsed.extension_id, "addictedguys.vscode-har-explorer");
    assert_eq!(parsed.version.as_deref(), Some("1.0.0"));

    // version lowercased
    let parsed = RuleVSCode::parse_extension_id_from_path(
        "/files/Publisher/Extension/1.0.0-BETA/extension.vsix",
    )
    .unwrap();
    assert_eq!(parsed.version.as_deref(), Some("1.0.0-beta"));
}
