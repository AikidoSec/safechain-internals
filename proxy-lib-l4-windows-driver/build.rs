#[cfg(target_os = "windows")]
fn main() -> Result<(), wdk_build::ConfigError> {
    use std::{env, fs, path::PathBuf};

    use bindgen::Builder;
    use wdk_build::{ApiSubset, BuilderExt, Config};

    let config = Config::from_env_auto()?;
    config.configure_binary_build()?;

    let mut header_contents = config.bindgen_header_contents([ApiSubset::Base])?;
    header_contents.push_str(
        "#ifndef NDIS_SUPPORT_NDIS6\n#define NDIS_SUPPORT_NDIS6 1\n#endif\n\
         #ifndef NDIS_SUPPORT_NDIS61\n#define NDIS_SUPPORT_NDIS61 1\n#endif\n\
         #include \"fwpsk.h\"\n",
    );

    let out_dir =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set for build scripts"));
    let header_path = out_dir.join("wfp_bindings.h");
    let bindings_path = out_dir.join("wfp_bindings.rs");

    fs::write(&header_path, header_contents)
        .map_err(|source| wdk_build::IoError::with_path(&header_path, source))?;

    let bindings = Builder::wdk_default(&config)?
        .header(
            header_path
                .to_str()
                .expect("bindgen header path must be valid UTF-8"),
        )
        .layout_tests(false)
        .allowlist_type("FWPS_CALLOUT1")
        .allowlist_type("FWPS_INCOMING_VALUES0")
        .allowlist_type("FWPS_INCOMING_VALUE0")
        .allowlist_type("FWPS_FILTER1")
        .allowlist_type("FWPS_CLASSIFY_OUT0")
        .allowlist_type("FWPS_INCOMING_METADATA_VALUES0")
        .allowlist_type("FWPS_CONNECT_REQUEST0")
        .allowlist_type("FWP_VALUE0")
        .allowlist_type("FWP_BYTE_BLOB")
        .allowlist_type("FWP_BYTE_ARRAY16")
        .allowlist_function("FwpsCalloutRegister1")
        .allowlist_function("FwpsCalloutUnregisterByKey0")
        .allowlist_function("FwpsRedirectHandleCreate0")
        .allowlist_function("FwpsRedirectHandleDestroy0")
        .allowlist_function("FwpsAcquireClassifyHandle0")
        .allowlist_function("FwpsReleaseClassifyHandle0")
        .allowlist_function("FwpsAcquireWritableLayerDataPointer0")
        .allowlist_function("FwpsApplyModifiedLayerData0")
        .allowlist_function("FwpsQueryConnectionRedirectState0")
        .generate()
        .expect("bindgen should generate WFP bindings");

    bindings
        .write_to_file(&bindings_path)
        .map_err(|source| wdk_build::IoError::with_path(&bindings_path, source))?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() {}
