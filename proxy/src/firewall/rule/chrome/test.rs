use crate::firewall::malware_list::PackageVersion;
use rama::http::{Body, Request, Uri};

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
}

#[test]
fn test_normalize_chrome_malware_key_known_entries() {
    let key_1 =
        "Malicious Extension - Chrome Web Store@lajondecmobodlejlcjllhojikagldgd".to_owned();
    assert_eq!(
        RuleChrome::normalize_malware_key(key_1),
        "lajondecmobodlejlcjllhojikagldgd"
    );

    let key_2 =
        "Into the Black Hole - Chrome Web Store@faeadnfmdfamenfhaipofoffijhlnkif".to_owned();
    assert_eq!(
        RuleChrome::normalize_malware_key(key_2),
        "faeadnfmdfamenfhaipofoffijhlnkif"
    );

    let key_3 = "  Something@FAEADNFMD FAMENFHAIPOFOFFIJHLNKIF  ".replace(' ', "");
    assert_eq!(
        RuleChrome::normalize_malware_key(key_3),
        "faeadnfmdfamenfhaipofoffijhlnkif"
    );
}
