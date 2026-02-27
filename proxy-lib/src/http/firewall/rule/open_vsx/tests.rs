use super::*;

#[test]
fn test_is_extension_install_asset_path() {
    // VSIXPackage paths should be blocked
    assert!(RuleOpenVsx::is_extension_install_asset_path(
        "/vscode/asset/oxc/oxc-vscode/1.47.0/Microsoft.VisualStudio.Services.VSIXPackage"
    ));
    assert!(RuleOpenVsx::is_extension_install_asset_path(
        "/vscode/asset/oxc/oxc-vscode/1.47.0/Microsoft.VisualStudio.Services.VSIXPackage/"
    ));
    assert!(RuleOpenVsx::is_extension_install_asset_path(
        "/open-vsx-mirror/vscode/asset/tomi/xasnippets/2.13.1/Microsoft.VisualStudio.Services.VSIXPackage"
    ));
    assert!(RuleOpenVsx::is_extension_install_asset_path(
        "/open-vsx-mirror/vscode/asset/tomi/xasnippets/2.13.1/Microsoft.VisualStudio.Services.VSIXPackage/"
    ));

    // Other asset types should NOT be blocked
    assert!(!RuleOpenVsx::is_extension_install_asset_path(
        "/vscode/asset/oxc/oxc-vscode/1.47.0/Microsoft.VisualStudio.Code.Manifest"
    ));
    assert!(!RuleOpenVsx::is_extension_install_asset_path(
        "/vscode/asset/oxc/oxc-vscode/1.47.0/Microsoft.VisualStudio.Services.VsixSignature"
    ));
    assert!(!RuleOpenVsx::is_extension_install_asset_path(
        "/vscode/asset/oxc/oxc-vscode/1.47.0/Microsoft.VisualStudio.Services.VsixManifest"
    ));
    assert!(!RuleOpenVsx::is_extension_install_asset_path(
        "/api/v2/extension/oxc/oxc-vscode/1.47.0"
    ));
}

#[test]
fn test_parse_extension_id_from_path() {
    let test_cases = vec![
        // open-vsx.org pattern
        (
            "/vscode/asset/oxc/oxc-vscode/1.47.0/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("oxc/oxc-vscode"),
        ),
        (
            "/vscode/asset/redhat/java/1.30.0/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("redhat/java"),
        ),
        (
            "vscode/asset/redhat/java/1.30.0/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("redhat/java"),
        ),
        // marketplace.cursorapi.com pattern
        (
            "/open-vsx-mirror/vscode/asset/tomi/xasnippets/2.13.1/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("tomi/xasnippets"),
        ),
        (
            "open-vsx-mirror/vscode/asset/tomi/xasnippets/2.13.1/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("tomi/xasnippets"),
        ),
        // Case-insensitive prefix matching
        (
            "/VSCODE/ASSET/oxc/oxc-vscode/1.47.0/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("oxc/oxc-vscode"),
        ),
        (
            "/Open-Vsx-Mirror/Vscode/Asset/tomi/xasnippets/2.13.1/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("tomi/xasnippets"),
        ),
        // Insufficient path segments
        ("/vscode/asset/oxc", None),
        ("/vscode/asset", None),
        ("/open-vsx-mirror/vscode/asset/tomi", None),
        // Unknown prefix
        ("/something/else/publisher/extension/version/file", None),
    ];

    for (input, expected) in test_cases {
        let parsed = RuleOpenVsx::parse_extension_id_from_path(input).map(|v| v.extension_id);
        assert_eq!(parsed.as_deref(), expected, "input: '{input}'");
    }
}

#[test]
fn test_parse_extension_id_from_path_preserves_case() {
    // Publisher and extension names preserve original case; matching happens case-insensitively at lookup
    let test_cases = vec![
        (
            "/vscode/asset/RedHat/java/1.30.0/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("RedHat/java"),
        ),
        (
            "/open-vsx-mirror/vscode/asset/Tomi/XaSnippets/2.13.1/Microsoft.VisualStudio.Services.VSIXPackage",
            Some("Tomi/XaSnippets"),
        ),
    ];

    for (input, expected) in test_cases {
        let parsed = RuleOpenVsx::parse_extension_id_from_path(input).map(|v| v.extension_id);
        assert_eq!(
            parsed.as_deref(),
            expected,
            "Failed to parse path: {}",
            input
        );
    }
}
