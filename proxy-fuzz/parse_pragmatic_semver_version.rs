#![no_main]

// NOTE: once refactor of netbench code is merged,
// we can use safechain_proxy_lib. In the current main version
// of safechain_proxy however we are still dealing with a binary only,
// so this is for now the easiest way to include that code and be able to test it
mod pragmatic_semver {
    #![allow(unused)]

    include!("../proxy/src/firewall/version/pragmatic_semver.rs");
}
use self::pragmatic_semver::PragmaticSemver;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return;
    };
    let _ = PragmaticSemver::parse(s);
});
