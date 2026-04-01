use std::fmt;

use crate::{endpoint_protection::EcosystemKey, package::name_formatter::PackageNameFormatter};

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

pub struct PolicyEvaluator<F: PackageNameFormatter> {
    config: RemoteEndpointConfig<F>,
}

impl<F: PackageNameFormatter> fmt::Debug for PolicyEvaluator<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEvaluator")
            .field("config", &self.config)
            .finish()
    }
}

impl<F: PackageNameFormatter> Clone for PolicyEvaluator<F> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

impl<F: PackageNameFormatter> PolicyEvaluator<F> {
    pub fn new(config: RemoteEndpointConfig<F>) -> Self {
        Self { config }
    }

    pub fn evaluate_package_install(
        &self,
        ecosystem: &EcosystemKey,
        package_name: &F::PackageName,
    ) -> PackagePolicyDecision {
        self.config
            .map_ecosystem_config(ecosystem, |config| {
                Self::evaluate_package_install_for_ecosystem_config(config, package_name)
            })
            .unwrap_or(PackagePolicyDecision::Defer)
    }

    fn evaluate_package_install_for_ecosystem_config(
        ecosystem_cfg: &EcosystemConfig<F>,
        package_name: &F::PackageName,
    ) -> PackagePolicyDecision {
        // Explicitly rejected packages
        if ecosystem_cfg
            .exceptions
            .rejected_packages
            .contains(package_name)
        {
            tracing::info!(
                package = %package_name,
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
                package = %package_name,
                "package is explicitly allowed by endpoint protection config"
            );
            return PackagePolicyDecision::Allow;
        }

        // Block all installs
        if ecosystem_cfg.block_all_installs {
            tracing::info!(
                package = %package_name,
                "all package installs are blocked by endpoint protection config"
            );
            return PackagePolicyDecision::BlockAll;
        }

        // Request install
        if ecosystem_cfg.request_installs {
            tracing::info!(
                package = %package_name,
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
