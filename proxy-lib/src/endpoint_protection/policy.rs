use super::{EcosystemConfig, RemoteEndpointConfig};
use rama::telemetry::tracing;

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
        // Explicitly rejected packages
        if ecosystem_cfg
            .exceptions
            .rejected_packages
            .contains(package_name)
        {
            tracing::info!(
                package = package_name,
                "package is explicitly blocked by endpoint protection config"
            );
            return PackagePolicyDecision::Rejected;
        }

        // Explicitly allowed packages
        if ecosystem_cfg
            .exceptions
            .allowed_packages
            .contains(package_name)
        {
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
