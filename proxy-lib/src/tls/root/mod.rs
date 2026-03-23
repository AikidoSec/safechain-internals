#[cfg(not(test))]
mod ca;
#[cfg(not(test))]
pub(super) use self::ca::new_root_tls_crt_key_pair;

#[cfg(test)]
mod ca_test;
#[cfg(test)]
pub(super) use self::ca_test::new_root_tls_crt_key_pair;
