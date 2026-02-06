use super::*;

#[test]
fn test_parse_package_from_nuget_api_v3_path() {
    let parse_result = RuleNuget::parse_package_from_path(
        "/v3-flatcontainer/newtonsoft.json/13.0.5-beta1/newtonsoft.json.13.0.5-beta1.nupkg",
    );

    assert!(
        parse_result.is_some(),
        "parse_result did not contain a nuget package"
    );

    let nuget_package = parse_result.unwrap();

    assert_eq!(nuget_package.fully_qualified_name, "newtonsoft.json");
    assert_eq!(
        nuget_package.version,
        PragmaticSemver::parse("13.0.5-beta1").unwrap()
    );
}

#[test]
fn test_parse_package_from_nuget_api_v2_path() {
    let parse_result =
        RuleNuget::parse_package_from_path("/api/v2/package/safechaintest/0.0.1-security");

    assert!(
        parse_result.is_some(),
        "parse_result did not contain a nuget package"
    );

    let nuget_package = parse_result.unwrap();

    assert_eq!(nuget_package.fully_qualified_name, "safechaintest");
    assert_eq!(
        nuget_package.version,
        PragmaticSemver::parse("0.0.1-security").unwrap()
    );
}
