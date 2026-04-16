use super::*;

#[test]
fn bindgen_wfp_constants_match_expected_values() {
    assert_eq!(FWP_UINT16, 2);
    assert_eq!(FWP_UINT32, 3);
    assert_eq!(FWP_BYTE_ARRAY16_TYPE, 11);
    assert_eq!(FWPS_CONNECTION_NOT_REDIRECTED, 0);
    assert_eq!(FWPS_CONNECTION_REDIRECTED_BY_SELF, 1);
    assert_eq!(FWPS_CONNECTION_REDIRECTED_BY_OTHER, 2);
    assert_eq!(FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF, 3);
}
