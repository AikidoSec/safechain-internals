use crate::firewall::malware_list::{
    ListDataEntry, MalwareListEntryFormatter, PackageVersion, Reason,
};
use rama::http::{Body, Request, Uri};

use super::malware_key::ChromeMalwareListEntryFormatter;
use super::*;

#[test]
fn test_parse_crx_download_url() {
    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.googleusercontent.com/crx/blobs/AV8Xwo6UfyG1svQNvX84OhvpXB-Xw-uQDkg-cYbGRZ1gTKj4oShAxmclsKXkB0kLKqSPOZKKKAM2nElpPWIO-TMWGIZoe0XewyHPPrbTLd4pehbXVSMHQGUvXt6EYD_UJ_XoAMZSmuU75EcMvYc0IzAknEyj-bKQuwE5Rw/GLNPJGLILKICBCKJPBGCFKOGEBGLLEMB_6_45_0_0.crx",
        ))
        .body(Body::empty())
        .unwrap();

    let result = RuleChrome::parse_crx_download_url(&req);
    assert!(result.is_some());

    let (extension_id, version) = result.unwrap();
    assert_eq!(extension_id.as_str(), "GLNPJGLILKICBCKJPBGCFKOGEBGLLEMB");
    assert_eq!(version, PackageVersion::Unknown("6.45.0.0".into()));
}

#[test]
fn test_version_matches() {
    let test_cases = vec![
        // (entry_version, observed_version, expected_match)
        ("1.0.0", "1.0.0", true),
        ("*", "1.0.0", true),
        ("6.45.0.0", "6.45.0.0", true),
        ("6.45.0.0", "1.0.0.0", false),
        ("6.45.0", "6.45.0.0", true),
        ("6.45.0.0", "6.45.0", true),
        ("6.45.0", "6.45.0.0", true),
        ("6.45.0.1", "6.45.0", false),
        ("14.1270", "14.1270.0.0", true),
        ("14.1270.0.0", "14.1270", true),
        ("1.0.0.0", "1.0.1.0", false),
        ("1.2.3.4", "1.2.3.5", false),
        ("10.0", "10.0.0.1", false),
        ("1.0", "1.0.0.1", false),
    ];

    for (entry, observed, expected) in test_cases {
        let entry_v = if entry == "*" {
            PackageVersion::Any
        } else {
            PackageVersion::Unknown(entry.into())
        };
        let observed_v = PackageVersion::Unknown(observed.into());

        assert_eq!(
            RuleChrome::version_matches(&entry_v, &observed_v),
            expected,
            "Failed for entry: {}, observed: {}",
            entry,
            observed
        );
    }
}

#[test]
fn test_normalize_chrome_malware_key_known_entries() {
    let formatter = ChromeMalwareListEntryFormatter;
    let make_entry = |name: &str| ListDataEntry {
        package_name: name.to_string(),
        version: PackageVersion::Any,
        reason: Reason::Malware,
    };

    let key_1 =
        "Malicious Extension - Chrome Web Store@lajondecmobodlejlcjllhojikagldgd".to_owned();
    assert_eq!(
        formatter.format(&make_entry(key_1.as_str())),
        "lajondecmobodlejlcjllhojikagldgd"
    );

    let key_2 =
        "Into the Black Hole - Chrome Web Store@faeadnfmdfamenfhaipofoffijhlnkif".to_owned();
    assert_eq!(
        formatter.format(&make_entry(key_2.as_str())),
        "faeadnfmdfamenfhaipofoffijhlnkif"
    );

    let key_3 = "  Something@FAEADNFMD FAMENFHAIPOFOFFIJHLNKIF  ".replace(' ', "");
    assert_eq!(
        formatter.format(&make_entry(key_3.as_str())),
        "faeadnfmdfamenfhaipofoffijhlnkif"
    );
}
