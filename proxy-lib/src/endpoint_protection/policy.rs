use std::collections::HashSet;

use rama::utils::str::arcstr::ArcStr;
use rama::telemetry::tracing;

use super::{EcosystemConfig, RemoteEndpointConfig};

/// `*` matches any substring (including empty). Only `*` is special; this is glob-style, not full regex.
fn glob_matches(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = text;

    if let Some(first) = parts.first()
        && !first.is_empty()
    {
        if !rest.starts_with(first) {
            return false;
        }
        rest = &rest[first.len()..];
    }
    
    if parts.len() <= 1 {
        return true;
    }

    for segment in &parts[1..parts.len() - 1] {
        if segment.is_empty() {
            continue;
        }
        match rest.find(segment) {
            Some(idx) => rest = &rest[idx + segment.len()..],
            None => return false,
        }
    }

    let last = parts[parts.len() - 1];
    if last.is_empty() {
        true
    } else {
        rest.ends_with(last)
    }
}

fn exception_list_matches(entries: &HashSet<ArcStr>, package_name: &str) -> bool {
    entries
        .iter()
        .any(|entry| glob_matches(entry.as_str(), package_name))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagePolicyDecision {
    /// No policy rule matched — defer to the next check (e.g. the malware list).
    Defer,
    /// An explicit allow rule matched — bypass all further checks for this package.
    Allow,
    /// Package is in the `rejected_packages` list — block immediately.
    Rejected,
    /// `block_all_installs` is enabled — block all installs for this ecosystem.
    BlockAll,
    /// `request_installs` is enabled — block pending approval.
    RequestInstall,
}

#[derive(Debug, Clone)]
pub struct PolicyEvaluator {
    config: RemoteEndpointConfig,
}

impl PolicyEvaluator {
    pub fn new(config: RemoteEndpointConfig) -> Self {
        Self { config }
    }

    pub fn evaluate_package_install(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> PackagePolicyDecision {
        let ecosystem_config = self.config.get_ecosystem_config(ecosystem);
        let Some(ecosystem_cfg) = ecosystem_config.config() else {
            return PackagePolicyDecision::Defer;
        };

        Self::evaluate_package_install_for_ecosystem_config(
            ecosystem_cfg,
            &package_name.to_ascii_lowercase(),
        )
    }

    fn evaluate_package_install_for_ecosystem_config(
        ecosystem_cfg: &EcosystemConfig,
        package_name: &str,
    ) -> PackagePolicyDecision {
        // Explicitly rejected packages (exact match or `*` glob)
        if exception_list_matches(&ecosystem_cfg.exceptions.rejected_packages, package_name) {
            tracing::info!(
                package = package_name,
                "package is explicitly blocked by endpoint protection config"
            );
            return PackagePolicyDecision::Rejected;
        }

        // Explicitly allowed packages (exact match or `*` glob)
        if exception_list_matches(&ecosystem_cfg.exceptions.allowed_packages, package_name) {
            tracing::info!(
                package = package_name,
                "package is explicitly allowed by endpoint protection config"
            );
            return PackagePolicyDecision::Allow;
        }

        // Block all installs
        if ecosystem_cfg.block_all_installs {
            tracing::info!(
                package = package_name,
                "all package installs are blocked by endpoint protection config"
            );
            return PackagePolicyDecision::BlockAll;
        }

        // Request install
        if ecosystem_cfg.request_installs {
            tracing::info!(
                package = package_name,
                "package install requires approval by endpoint protection config"
            );
            return PackagePolicyDecision::RequestInstall;
        }

        PackagePolicyDecision::Defer
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
