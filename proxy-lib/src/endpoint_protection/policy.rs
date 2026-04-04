use std::{collections::HashMap, fmt, hash::Hash, sync::Arc};

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;

use crate::{endpoint_protection::EcosystemKey, package::name_formatter::PackageName};

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

pub struct PolicyEvaluator<K> {
    config: RemoteEndpointConfig,
    cached: Arc<ArcSwapOption<CachedPolicyView<K>>>,
    refresh_lock: Arc<Mutex<()>>,
}

impl<K> fmt::Debug for PolicyEvaluator<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEvaluator")
            .field("config", &self.config)
            .finish()
    }
}

impl<K> Clone for PolicyEvaluator<K> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cached: self.cached.clone(),
            refresh_lock: self.refresh_lock.clone(),
        }
    }
}

impl<K> PolicyEvaluator<K> {
    pub fn new(config: RemoteEndpointConfig) -> Self {
        Self {
            config,
            cached: Arc::new(ArcSwapOption::const_empty()),
            refresh_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn evaluate_package_install(
        &self,
        ecosystem: &EcosystemKey,
        package_name: &K,
    ) -> PackagePolicyDecision
    where
        K: PackageName + Eq + Hash + fmt::Display,
    {
        self.refresh_typed_cache_if_stale();

        self.cached
            .load()
            .as_ref()
            .and_then(|cached| cached.configs.get(ecosystem))
            .map(|config| {
                Self::evaluate_package_install_for_typed_ecosystem_config(config, package_name)
            })
            .unwrap_or(PackagePolicyDecision::Defer)
    }

    fn refresh_typed_cache_if_stale(&self)
    where
        K: PackageName + Eq + Hash,
    {
        let current_revision = self.config.revision();
        if self
            .cached
            .load()
            .as_ref()
            .is_some_and(|cached| cached.revision == current_revision)
        {
            return;
        }

        let _guard = self.refresh_lock.lock();

        if self
            .cached
            .load()
            .as_ref()
            .is_some_and(|cached| cached.revision == current_revision)
        {
            return;
        }

        let configs = self.config.map_ecosystems(|ecosystems| {
            ecosystems
                .iter()
                .map(|(key, config)| (key.clone(), TypedEcosystemConfig::from_raw(config)))
                .collect()
        });

        self.cached.store(Some(Arc::new(CachedPolicyView {
            revision: current_revision,
            configs: configs.unwrap_or_default(),
        })));
    }

    #[cfg(test)]
    fn evaluate_package_install_for_ecosystem_config(
        ecosystem_cfg: &TypedEcosystemConfig<K>,
        package_name: &K,
    ) -> PackagePolicyDecision
    where
        K: PackageName + Eq + Hash + fmt::Display,
    {
        Self::evaluate_package_install_for_typed_ecosystem_config(ecosystem_cfg, package_name)
    }

    fn evaluate_package_install_for_typed_ecosystem_config(
        ecosystem_cfg: &TypedEcosystemConfig<K>,
        package_name: &K,
    ) -> PackagePolicyDecision
    where
        K: Eq + Hash + fmt::Display,
    {
        // Explicitly rejected packages
        if ecosystem_cfg.rejected_packages.contains(package_name) {
            tracing::info!(
                package = %package_name,
                "package is explicitly blocked by endpoint protection config"
            );
            return PackagePolicyDecision::Rejected;
        }

        // Explicitly allowed packages
        if ecosystem_cfg.allowed_packages.contains(package_name) {
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

struct CachedPolicyView<K> {
    revision: u64,
    configs: HashMap<EcosystemKey, TypedEcosystemConfig<K>>,
}

struct TypedEcosystemConfig<K> {
    block_all_installs: bool,
    request_installs: bool,
    allowed_packages: std::collections::HashSet<K>,
    rejected_packages: std::collections::HashSet<K>,
}

impl<K> TypedEcosystemConfig<K> {
    fn from_raw(raw: &EcosystemConfig) -> Self
    where
        K: PackageName + Eq + Hash,
    {
        Self {
            block_all_installs: raw.block_all_installs,
            request_installs: raw.request_installs,
            allowed_packages: raw
                .exceptions
                .allowed_packages
                .iter()
                .map(|package| K::normalize(package.as_str()))
                .collect(),
            rejected_packages: raw
                .exceptions
                .rejected_packages
                .iter()
                .map(|package| K::normalize(package.as_str()))
                .collect(),
        }
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
