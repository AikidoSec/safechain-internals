use rama::utils::str::arcstr::ArcStr;

fn chrome_package_name_from_str(s: &str) -> ChromePackageName {
    // Example value from malware list:
    //   "Malicious Extension - Chrome Web Store@lajondecmobodlejlcjllhojikagldgd"
    let raw = s.trim();
    let extension_id = raw.rsplit_once('@').map(|(_, id)| id).unwrap_or(raw);
    ChromePackageName(extension_id.to_ascii_lowercase().into())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ChromePackageName(ArcStr);

crate::package::name_formatter::decl_arc_str_package_name!(
    ChromePackageName,
    ChromePackageNameRef,
    chrome_package_name_from_str
);
