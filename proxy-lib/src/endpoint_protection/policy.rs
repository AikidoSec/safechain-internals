use arc_swap::ArcSwapOption;
use std::{fmt, hash::Hash, sync::Arc};
use tokio::sync::broadcast;

use rama::{graceful::ShutdownGuard, telemetry::tracing};

use super::{EcosystemConfig, EndpointConfig, RemoteEndpointConfig};
use crate::utils::time::{SystemDuration, SystemTimestampMilliseconds};
use crate::{endpoint_protection::EcosystemKey, package::name_formatter::PackageName};

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
    cached: Arc<ArcSwapOption<TypedEcosystemConfig<K>>>,
}

impl<K> fmt::Debug for PolicyEvaluator<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEvaluator").finish()
    }
}

impl<K> Clone for PolicyEvaluator<K> {
    fn clone(&self) -> Self {
        Self {
            cached: self.cached.clone(),
        }
    }
}

impl<K> PolicyEvaluator<K> {
    pub fn new(guard: ShutdownGuard, ecosystem: EcosystemKey, config: RemoteEndpointConfig) -> Self
    where
        K: PackageName + Eq + Hash + Send + Sync + 'static,
    {
        let (current, updates) = config.subscribe();
        let cached = Arc::new(ArcSwapOption::const_empty());
        Self::refresh_cached_policy_view(&cached, &ecosystem, current.as_ref());

        let cached_clone = cached.clone();
        tokio::spawn(Self::run_update_loop(
            guard,
            ecosystem,
            config,
            cached_clone,
            updates,
        ));

        Self { cached }
    }

    pub fn evaluate_package_install(&self, package_name: &K) -> PackagePolicyDecision
    where
        K: Eq + Hash + fmt::Display,
    {
        self.cached
            .load()
            .as_ref()
            .map(|config| {
                Self::evaluate_package_install_for_typed_ecosystem_config(config, package_name)
            })
            .unwrap_or(PackagePolicyDecision::Defer)
    }

    pub fn package_age_cutoff_ts(
        &self,
        default_cutoff_age: SystemDuration,
    ) -> SystemTimestampMilliseconds {
        self.cached
            .load()
            .as_ref()
            .and_then(|config| config.minimum_allowed_age_timestamp)
            .unwrap_or_else(|| SystemTimestampMilliseconds::now() - default_cutoff_age)
    }

    fn refresh_cached_policy_view(
        cached: &Arc<ArcSwapOption<TypedEcosystemConfig<K>>>,
        ecosystem: &EcosystemKey,
        config: &Option<EndpointConfig>,
    ) where
        K: PackageName + Eq + Hash,
    {
        let typed_config = config
            .as_ref()
            .and_then(|config| config.ecosystems.get(ecosystem))
            .map(TypedEcosystemConfig::from_raw)
            .map(Arc::new);
        cached.store(typed_config);
    }

    async fn run_update_loop(
        guard: ShutdownGuard,
        ecosystem: EcosystemKey,
        config: RemoteEndpointConfig,
        cached: Arc<ArcSwapOption<TypedEcosystemConfig<K>>>,
        mut updates: broadcast::Receiver<Arc<Option<EndpointConfig>>>,
    ) where
        K: PackageName + Eq + Hash,
    {
        loop {
            tokio::select! {
                _ = guard.cancelled() => {
                    tracing::debug!("policy evaluator update task cancelled; exit");
                    return;
                }
                result = updates.recv() => {
                    match result {
                        Ok(config) => {
                            Self::refresh_cached_policy_view(&cached, &ecosystem, config.as_ref());
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let current = config.current();
                            Self::refresh_cached_policy_view(&cached, &ecosystem, current.as_ref());
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::debug!("policy evaluator update channel closed; exit");
                            return;
                        }
                    }
                }
            }
        }
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
        if ecosystem_cfg.rejected_packages.contains(package_name) {
            tracing::info!(
                package = %package_name,
                "package is explicitly blocked by endpoint protection config"
            );
            return PackagePolicyDecision::Rejected;
        }

        if ecosystem_cfg.allowed_packages.contains(package_name) {
            tracing::info!(
                package = %package_name,
                "package is explicitly allowed by endpoint protection config"
            );
            return PackagePolicyDecision::Allow;
        }

        if ecosystem_cfg.block_all_installs {
            tracing::info!(
                package = %package_name,
                "all package installs are blocked by endpoint protection config"
            );
            return PackagePolicyDecision::BlockAll;
        }

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

struct TypedEcosystemConfig<K> {
    block_all_installs: bool,
    request_installs: bool,
    minimum_allowed_age_timestamp: Option<SystemTimestampMilliseconds>,
    allowed_packages: std::collections::HashSet<K>,
    rejected_packages: std::collections::HashSet<K>,
}

impl<K> TypedEcosystemConfig<K> {
    fn from_raw(raw: &EcosystemConfig) -> Self
    where
        K: PackageName + Eq + Hash,
    {
        // destructure first, protects against future changes
        // to struct (e.g. in case we add fields, this will fail to compile,
        // forcing us to deal with it)
        let EcosystemConfig {
            block_all_installs,
            request_installs,
            minimum_allowed_age_timestamp,
            exceptions,
        } = raw;

        Self {
            block_all_installs: *block_all_installs,
            request_installs: *request_installs,
            minimum_allowed_age_timestamp: *minimum_allowed_age_timestamp,
            allowed_packages: exceptions
                .allowed_packages
                .iter()
                .map(|package| K::normalize(package.as_str()))
                .collect(),
            rejected_packages: exceptions
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
