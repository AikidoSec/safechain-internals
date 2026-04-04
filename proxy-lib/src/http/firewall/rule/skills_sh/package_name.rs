use rama::utils::str::arcstr::ArcStr;

use crate::package::name_formatter::PackageName;

/// Formats a skills.sh malware-list entry as `owner/repo` (lowercase).
///
/// The malware list uses three-part names (`owner/repo/skill-name`) because a
/// single repository may contain multiple skills.  A git pull URL, however,
/// only ever identifies the repository (`owner/repo`), so we index the trie by
/// that prefix so that any listed skill in a repository triggers a block.
fn skill_sh_package_name_from_str(s: &str) -> SkillsShPackageName {
    let name = s.trim().to_ascii_lowercase();
    // Take only the first two slash-delimited segments (owner/repo),
    // discarding the skill-name suffix.
    match name.splitn(3, '/').collect::<Vec<_>>().as_slice() {
        [owner, repo, ..] if !owner.is_empty() && !repo.is_empty() => {
            SkillsShPackageName(format!("{owner}/{repo}").into())
        }
        _ => SkillsShPackageName(name.into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct SkillsShPackageName(ArcStr);

impl PackageName for SkillsShPackageName {
    #[inline(always)]
    fn normalize(package_name: &str) -> Self {
        skill_sh_package_name_from_str(package_name)
    }
}

crate::package::name_formatter::decl_arc_str_package_name!(
    SkillsShPackageName,
    skill_sh_package_name_from_str
);
