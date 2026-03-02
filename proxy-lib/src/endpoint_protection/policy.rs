use super::{EcosystemConfig, RemoteEndpointConfig};
use rama::telemetry::tracing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagePolicyDecision {
    NoMatch,
    Allow,
    Block,
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
            return PackagePolicyDecision::NoMatch;
        };

        Self::evaluate_package_install_for_ecosystem_config(ecosystem_cfg, package_name)
    }

    fn evaluate_package_install_for_ecosystem_config(
        ecosystem_cfg: &EcosystemConfig,
        package_name: &str,
    ) -> PackagePolicyDecision {
        if ecosystem_cfg
            .exceptions
            .allowed_packages
            .iter()
            .any(|pkg| pkg.as_str() == package_name)
        {
            tracing::info!(
                package = package_name,
                "package is explicitly allowed by endpoint protection config"
            );
            return PackagePolicyDecision::Allow;
        }

        if ecosystem_cfg.block_all_installs {
            tracing::info!(
                package = package_name,
                "all package installs are blocked by endpoint protection config"
            );
            return PackagePolicyDecision::Block;
        }

        if ecosystem_cfg
            .exceptions
            .rejected_packages
            .iter()
            .any(|pkg| pkg.as_str() == package_name)
        {
            tracing::info!(
                package = package_name,
                "package is explicitly blocked by endpoint protection config"
            );
            return PackagePolicyDecision::Block;
        }

        PackagePolicyDecision::NoMatch
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
