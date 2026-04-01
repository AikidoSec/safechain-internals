use rama::utils::str::arcstr::ArcStr;

use crate::package::name_formatter::PackageNameFormatter;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub(in crate::http::firewall) struct ChromePackageNameFormatter;

impl PackageNameFormatter for ChromePackageNameFormatter {
    type PackageName = ChromePackageName;

    #[inline(always)]
    fn format_package_name(&self, package_name: &str) -> Self::PackageName {
        chrome_package_name_from_str(package_name)
    }
}

fn chrome_package_name_from_str(s: &str) -> ChromePackageName {
    // Example value from malware list:
    //   "Malicious Extension - Chrome Web Store@lajondecmobodlejlcjllhojikagldgd"
    let raw = s.trim();
    let extension_id = raw.rsplit_once('@').map(|(_, id)| id).unwrap_or(raw);
    ChromePackageName(extension_id.to_ascii_lowercase().into())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::http::firewall) struct ChromePackageName(ArcStr);

crate::package::name_formatter::decl_arc_str_package_name!(
    ChromePackageName,
    chrome_package_name_from_str
);
