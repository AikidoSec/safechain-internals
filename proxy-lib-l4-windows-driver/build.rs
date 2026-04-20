#[cfg(target_os = "windows")]
use std::path::PathBuf;

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
    let rc_path = out_dir.join("safechain_lib_l4_proxy_windows_driver.rc");
    let res_path = out_dir.join("safechain_lib_l4_proxy_windows_driver.res");

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

    let version = env!("CARGO_PKG_VERSION");
    let [major, minor, patch] = parse_version_triplet(version);
    let file_version_commas = format!("{major},{minor},{patch},0");
    let file_version_dots = format!("{major}.{minor}.{patch}.0");
    let rc_contents = format!(
        r#"#include <winver.h>

VS_VERSION_INFO VERSIONINFO
 FILEVERSION {file_version_commas}
 PRODUCTVERSION {file_version_commas}
 FILEFLAGSMASK 0x3fL
#ifdef _DEBUG
 FILEFLAGS VS_FF_DEBUG
#else
 FILEFLAGS 0x0L
#endif
 FILEOS VOS_NT_WINDOWS32
 FILETYPE VFT_DRV
 FILESUBTYPE VFT2_DRV_SYSTEM
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "Aikido Security BV\0"
            VALUE "FileDescription", "SafeChain L4 Proxy Windows Driver\0"
            VALUE "FileVersion", "{file_version_dots}\0"
            VALUE "InternalName", "safechain_lib_l4_proxy_windows_driver.sys\0"
            VALUE "LegalCopyright", "Copyright (c) Aikido Security BV\0"
            VALUE "OriginalFilename", "safechain_lib_l4_proxy_windows_driver.sys\0"
            VALUE "ProductName", "SafeChain L4 Proxy\0"
            VALUE "ProductVersion", "{file_version_dots}\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#
    );
    fs::write(&rc_path, rc_contents)
        .map_err(|source| wdk_build::IoError::with_path(&rc_path, source))?;

    let rc_exe = find_rc_exe().ok_or_else(|| {
        wdk_build::ConfigError::from(wdk_build::IoError::with_path(
            "rc.exe",
            std::io::Error::new(std::io::ErrorKind::NotFound, "Windows rc.exe not found"),
        ))
    })?;
    let mut rc_command = std::process::Command::new(&rc_exe);
    rc_command
        .arg("/nologo")
        .arg(format!("/fo{}", res_path.display()));
    for include_path in config.include_paths()? {
        rc_command.arg(format!("/I{}", include_path.display()));
    }
    if let Some(include_root) = find_windows_sdk_include_root() {
        rc_command.arg(format!("/I{}", include_root.join("shared").display()));
        rc_command.arg(format!("/I{}", include_root.join("um").display()));
    }
    let status = rc_command
        .arg(&rc_path)
        .status()
        .map_err(|source| wdk_build::IoError::with_path(&rc_exe, source))?;
    if !status.success() {
        return Err(wdk_build::ConfigError::from(wdk_build::IoError::with_path(
            &rc_exe,
            std::io::Error::other(format!("rc.exe failed with status {status}")),
        )));
    }

    println!("cargo:rustc-link-arg-cdylib={}", res_path.display());

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() {}

#[cfg(target_os = "windows")]
fn parse_version_triplet(version: &str) -> [u16; 3] {
    let mut parts = version.split('.');
    let parse = |part: Option<&str>| -> u16 {
        part.expect("CARGO_PKG_VERSION should have three numeric parts")
            .parse()
            .expect("CARGO_PKG_VERSION should contain only numeric components")
    };
    [
        parse(parts.next()),
        parse(parts.next()),
        parse(parts.next()),
    ]
}

#[cfg(target_os = "windows")]
fn find_rc_exe() -> Option<PathBuf> {
    newest_windows_kit_version_dir(r"C:\Program Files (x86)\Windows Kits\10\bin")
        .map(|path| path.join("x64").join("rc.exe"))
        .filter(|path| path.exists())
}

#[cfg(target_os = "windows")]
fn find_windows_sdk_include_root() -> Option<PathBuf> {
    newest_windows_kit_version_dir(r"C:\Program Files (x86)\Windows Kits\10\Include")
        .filter(|path| path.join("um").join("winver.h").exists() && path.join("shared").exists())
}

#[cfg(target_os = "windows")]
fn newest_windows_kit_version_dir(root: &str) -> Option<PathBuf> {
    let mut candidates = std::fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().ok().is_some_and(|kind| kind.is_dir()))
        .filter_map(|entry| is_windows_kit_version_dir(&entry).then_some(entry.path()))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

#[cfg(target_os = "windows")]
fn is_windows_kit_version_dir(entry: &std::fs::DirEntry) -> bool {
    entry
        .file_name()
        .to_string_lossy()
        .split('.')
        .all(|segment| !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()))
}
