use super::*;

#[test]
fn test_generate_ec_p256_key() {
    let key = generate_ec_p256_key().unwrap();
    // verify it's an EC key on P-256
    let ec = key.ec_key().unwrap();
    let group = ec.group();
    let expected = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    assert_eq!(group.curve_name(), expected.curve_name());
}

#[test]
fn test_generate_int_ca_csr() {
    let key = generate_ec_p256_key().unwrap();
    let csr_pem = generate_int_ca_csr("test-device-id", &key).unwrap();
    let csr = X509Req::from_pem(&csr_pem).unwrap();

    // verify subject CN
    let subject = csr.subject_name();
    let cn_entry = subject
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .expect("CN entry present");
    let cn_openssl_str = cn_entry.data().as_utf8().unwrap();
    let cn_str: &str = cn_openssl_str.as_ref();
    assert_eq!(cn_str, "test-device-id");
}

#[test]
fn test_needs_renewal() {
    // already expired
    assert!(needs_renewal(0));
    // expires in 1 day → needs renewal (< 2 days threshold)
    let one_day = SystemTime::now() + Duration::from_secs(86400);
    let one_day_unix = one_day.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!(needs_renewal(one_day_unix));
    // expires in 3 days → does not need renewal
    let three_days = SystemTime::now() + Duration::from_secs(3 * 86400);
    let three_days_unix = three_days.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!(!needs_renewal(three_days_unix));
}
