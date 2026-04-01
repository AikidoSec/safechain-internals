use rama::utils::str::arcstr::ArcStr;

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct LowerCasePackageNameFormatter;

impl LowerCasePackageNameFormatter {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

impl super::PackageNameFormatter for LowerCasePackageNameFormatter {
    type PackageName = LowerCasePackageName;

    #[inline(always)]
    fn format_package_name(&self, raw_package_name: &str) -> Self::PackageName {
        lower_case_package_name_from_str(raw_package_name)
    }
}

fn lower_case_package_name_from_str(s: &str) -> LowerCasePackageName {
    LowerCasePackageName(s.to_ascii_lowercase().into())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LowerCasePackageName(ArcStr);

super::decl_arc_str_package_name!(LowerCasePackageName, lower_case_package_name_from_str);
