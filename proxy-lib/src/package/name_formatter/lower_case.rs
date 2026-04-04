use rama::utils::str::arcstr::ArcStr;

fn lower_case_package_name_from_str(s: &str) -> LowerCasePackageName {
    LowerCasePackageName(s.to_ascii_lowercase().into())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LowerCasePackageName(ArcStr);

impl super::PackageName for LowerCasePackageName {
    #[inline(always)]
    fn normalize(raw_package_name: &str) -> Self {
        lower_case_package_name_from_str(raw_package_name)
    }
}

super::decl_arc_str_package_name!(LowerCasePackageName, lower_case_package_name_from_str);
