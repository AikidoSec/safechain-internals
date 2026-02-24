#![no_main]

use safechain_proxy_lib::package::version::PragmaticSemver;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return;
    };
    let _ = PragmaticSemver::parse(s);
});
