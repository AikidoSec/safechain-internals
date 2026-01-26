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
    assert!(RuleChrome::version_matches(
        &PackageVersion::Any,
        &PackageVersion::Unknown("1.0.0".into())
    ));
    assert!(RuleChrome::version_matches(
        &PackageVersion::Any,
        &PackageVersion::Semver("1.0.0".parse().unwrap())
    ));

    let v1 = PackageVersion::Unknown("6.45.0.0".into());
    let v2 = PackageVersion::Unknown("6.45.0.0".into());
    let v3 = PackageVersion::Unknown("1.0.0.0".into());

    assert!(RuleChrome::version_matches(&v1, &v2));
    assert!(!RuleChrome::version_matches(&v1, &v3));

    let s_6450 = PackageVersion::Semver("6.45.0".parse().unwrap());
    let u_64500 = PackageVersion::Unknown("6.45.0.0".into());
    let u_6450 = PackageVersion::Unknown("6.45.0".into());
    let u_64501 = PackageVersion::Unknown("6.45.0.1".into());

    assert!(RuleChrome::version_matches(&s_6450, &u_64500));
    assert!(RuleChrome::version_matches(&u_64500, &s_6450));

    assert!(RuleChrome::version_matches(&u_6450, &u_64500));
    assert!(!RuleChrome::version_matches(&u_64501, &s_6450));
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
