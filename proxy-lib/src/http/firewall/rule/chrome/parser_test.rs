use rama::http::{Body, Request, Uri};

use crate::package::version::{PackageVersion, PragmaticSemver};

use super::parse_crx_download_url;

#[test]
fn test_parse_crx_download_url() {
    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.googleusercontent.com/crx/blobs/AV8Xwo6UfyG1svQNvX84OhvpXB-Xw-uQDkg-cYbGRZ1gTKj4oShAxmclsKXkB0kLKqSPOZKKKAM2nElpPWIO-TMWGIZoe0XewyHPPrbTLd4pehbXVSMHQGUvXt6EYD_UJ_XoAMZSmuU75EcMvYc0IzAknEyj-bKQuwE5Rw/GLNPJGLILKICBCKJPBGCFKOGEBGLLEMB_6_45_0_0.crx",
        ))
        .body(Body::empty())
        .unwrap();

    let result = parse_crx_download_url(&req);
    assert!(result.is_some());

    let (extension_id, version) = result.unwrap();
    assert_eq!(extension_id.as_str(), "GLNPJGLILKICBCKJPBGCFKOGEBGLLEMB");
    assert_eq!(
        version,
        PackageVersion::Semver(PragmaticSemver::new_two_components(6, 45))
    );
}

#[test]
fn test_parse_update2_crx_download_url() {
    let req = Request::builder()
        .uri(Uri::from_static(
            "https://clients2.google.com/service/update2/crx?response=redirect&os=mac&arch=arm64&os_arch=arm64&prod=chromecrx&prodchannel=&prodversion=146.0.7680.177&lang=en-US&acceptformat=crx3,puff&x=id%3Dliecbddmkiiihnedobmlmillhodjkdmb%26installsource%3Dondemand%26uc&authuser=0",
        ))
        .body(Body::empty())
        .unwrap();

    let result = parse_crx_download_url(&req);
    assert!(result.is_some());

    let (extension_id, version) = result.unwrap();
    assert_eq!(extension_id.as_str(), "liecbddmkiiihnedobmlmillhodjkdmb");
    assert_eq!(version, PackageVersion::None);
}
