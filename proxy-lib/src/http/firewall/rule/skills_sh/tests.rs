use super::*;

use crate::package::{
    malware_list::ListDataEntry,
    version::PackageVersion,
};

// --- SkillsShEntryFormatter ---

#[test]
fn test_formatter_strips_skill_name() {
    let formatter = SkillsShEntryFormatter;
    let entry = ListDataEntry {
        package_name: "asklokesh/claudeskill-loki-mode/loki-mode".to_owned(),
        version: PackageVersion::Unknown("commit-dde60807afea".into()),
        reason: crate::package::malware_list::Reason::Telemetry,
    };
    assert_eq!(formatter.format(&entry), "asklokesh/claudeskill-loki-mode");
}

#[test]
fn test_formatter_lowercases() {
    let formatter = SkillsShEntryFormatter;
    let entry = ListDataEntry {
        package_name: "Owner/Repo/Skill".to_owned(),
        version: PackageVersion::None,
        reason: crate::package::malware_list::Reason::Malware,
    };
    assert_eq!(formatter.format(&entry), "owner/repo");
}

// --- parse_repo_from_path: with .git suffix ---

#[test]
fn test_parse_repo_git_suffix_info_refs() {
    let result = RuleSkillsSh::parse_repo_from_path("/owner/repo.git/info/refs");
    assert_eq!(result.as_deref(), Some("owner/repo"));
}

#[test]
fn test_parse_repo_git_suffix_upload_pack() {
    let result = RuleSkillsSh::parse_repo_from_path("/owner/repo.git/git-upload-pack");
    assert_eq!(result.as_deref(), Some("owner/repo"));
}

#[test]
fn test_parse_repo_git_suffix_receive_pack() {
    let result = RuleSkillsSh::parse_repo_from_path("/owner/repo.git/git-receive-pack");
    assert_eq!(result.as_deref(), Some("owner/repo"));
}

// --- parse_repo_from_path: without .git suffix ---

#[test]
fn test_parse_repo_no_git_suffix_info_refs() {
    let result = RuleSkillsSh::parse_repo_from_path("/owner/repo/info/refs");
    assert_eq!(result.as_deref(), Some("owner/repo"));
}

#[test]
fn test_parse_repo_no_git_suffix_upload_pack() {
    let result = RuleSkillsSh::parse_repo_from_path("/owner/repo/git-upload-pack");
    assert_eq!(result.as_deref(), Some("owner/repo"));
}

#[test]
fn test_parse_repo_no_git_suffix_receive_pack() {
    let result = RuleSkillsSh::parse_repo_from_path("/owner/repo/git-receive-pack");
    assert_eq!(result.as_deref(), Some("owner/repo"));
}

// --- parse_repo_from_path: normalisation ---

#[test]
fn test_parse_repo_lowercases_name() {
    let result = RuleSkillsSh::parse_repo_from_path("/Owner/Repo/git-upload-pack");
    assert_eq!(result.as_deref(), Some("owner/repo"));
}

// --- parse_repo_from_path: non-matches ---

#[test]
fn test_parse_repo_rejects_non_git_path() {
    let result = RuleSkillsSh::parse_repo_from_path("/owner/repo/releases/tag/v1.0.0");
    assert!(result.is_none(), "should be None for a non-git path");
}

#[test]
fn test_parse_repo_rejects_path_without_owner() {
    let result = RuleSkillsSh::parse_repo_from_path("/repo/git-upload-pack");
    assert!(result.is_none(), "should be None when there is no owner segment");
}
