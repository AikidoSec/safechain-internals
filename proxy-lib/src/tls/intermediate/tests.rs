use super::*;
use crate::storage::SyncSecrets;

fn make_test_cert(key: &PKey<Private>) -> X509 {
    let mut b = X509::builder().unwrap();
    let mut n = X509Name::builder().unwrap();
    n.append_entry_by_nid(Nid::COMMONNAME, "test").unwrap();
    let n = n.build();
    b.set_subject_name(&n).unwrap();
    b.set_issuer_name(&n).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap()).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build()
}

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
fn test_csr_extensions() {
    let key = generate_ec_p256_key().unwrap();
    let csr_pem = generate_int_ca_csr("test-device-id", &key).unwrap();
    let csr = X509Req::from_pem(&csr_pem).unwrap();

    let extensions = csr.extensions().unwrap();
    let nids: Vec<Nid> = extensions.iter().map(|e| e.object().nid()).collect();
    assert!(
        nids.contains(&Nid::BASIC_CONSTRAINTS),
        "BasicConstraints extension missing"
    );
    assert!(
        nids.contains(&Nid::EXT_KEY_USAGE),
        "ExtendedKeyUsage extension missing"
    );
}

#[test]
fn test_asn1_time_to_unix_is_reasonable() {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let asn1_now = Asn1Time::days_from_now(0).unwrap();
    let result = asn1_time_to_unix(&asn1_now).unwrap();
    assert!(
        (result - now_unix).abs() < 10,
        "expected ~{now_unix}, got {result}"
    );
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

#[test]
fn test_needs_renewal_at_exact_threshold() {
    // exactly at the 2-day threshold → needs renewal (threshold >= not_after when equal)
    let threshold_time = SystemTime::now() + Duration::from_secs(RENEWAL_THRESHOLD_SECS);
    let threshold_unix = threshold_time
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(needs_renewal(threshold_unix));
}

#[test]
fn test_storage_load_empty_returns_none() {
    let secrets = SyncSecrets::new_in_memory("test");
    let result = load_keypair_from_secret_storage(&secrets).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_storage_store_and_load_roundtrip() {
    let secrets = SyncSecrets::new_in_memory("test");
    let key = generate_ec_p256_key().unwrap();
    let cert = make_test_cert(&key);

    let key_der = key.private_key_to_der_pkcs8().unwrap();
    let crt_der = cert.to_der().unwrap();
    let fp = cert.digest(MessageDigest::sha256()).unwrap().to_vec();
    let not_after_unix = asn1_time_to_unix(cert.not_after()).unwrap();

    store_keypair_in_secret_storage(&secrets, key_der.clone(), crt_der.clone(), fp, not_after_unix)
        .unwrap();

    let (loaded_key, loaded_crt, loaded_not_after) =
        load_keypair_from_secret_storage(&secrets)
            .unwrap()
            .expect("keypair should be present");

    assert_eq!(loaded_key, key_der);
    assert_eq!(loaded_crt, crt_der);
    assert_eq!(loaded_not_after, not_after_unix);
}

#[test]
fn test_storage_fingerprint_mismatch_returns_error() {
    let secrets = SyncSecrets::new_in_memory("test");
    let key = generate_ec_p256_key().unwrap();
    let cert = make_test_cert(&key);

    let key_der = key.private_key_to_der_pkcs8().unwrap();
    let crt_der = cert.to_der().unwrap();
    let wrong_fp = vec![0u8; 32];

    store_keypair_in_secret_storage(&secrets, key_der, crt_der, wrong_fp, 0).unwrap();

    let result = load_keypair_from_secret_storage(&secrets);
    assert!(result.is_err(), "expected fingerprint mismatch error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("fingerprint mismatch"),
        "unexpected error: {err_msg}"
    );
}
