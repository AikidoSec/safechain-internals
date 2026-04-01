use std::{fmt, time::Duration};

use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri},
};

use radix_trie::Trie;
use serde::{Deserialize, Serialize};

use crate::{
    package::{name_formatter::PackageNameFormatter, version::PackageVersion},
    storage::SyncCompactDataStorage,
    utils::remote_resource::{self, RemoteResource, RemoteResourceSpec},
};

/// How long to keep entries in the trie (7 days).
/// Entries older than this are irrelevant to the configured blocking window.
const MAX_ENTRY_AGE_SECS: i64 = 7 * 24 * 3600;

pub struct RemoteReleasedPackagesList<F: PackageNameFormatter> {
    trie: RemoteResource<ReleasedPackagesTrie<F>>,
}

impl<F: PackageNameFormatter> Clone for RemoteReleasedPackagesList<F> {
    fn clone(&self) -> Self {
        Self {
            trie: self.trie.clone(),
        }
    }
}

impl<F: PackageNameFormatter> fmt::Debug for RemoteReleasedPackagesList<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteReleasedPackagesList").finish()
    }
}

impl<F: PackageNameFormatter> RemoteReleasedPackagesList<F> {
    pub async fn try_new<C>(
        guard: ShutdownGuard,
        uri: Uri,
        sync_storage: SyncCompactDataStorage,
        client: C,
        formatter: F,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let (trie, _refresh_handle) = remote_resource::try_new(
            guard,
            sync_storage,
            client,
            ReleasedPackagesRemoteResource { uri, formatter },
        )
        .await
        .context("create new remote released packages list")?;

        Ok(Self { trie })
    }

    /// Returns true if the package was released recently (after `cutoff_secs`).
    ///
    /// NOTE: It is assumed that _package_name_ is pre-formatted by the callee,
    /// using the same formatter used here to insert the data.
    ///
    /// - `version = Some(v)`: only the specific version must be recent
    /// - `version = None`: true if ANY version of the package is recent
    pub fn is_recently_released(
        &self,
        package_name: &F::PackageName,
        version: Option<&PackageVersion>,
        cutoff_secs: i64,
    ) -> bool {
        let state_ref = self.trie.get();
        let Some(entries) = state_ref.get(package_name) else {
            return false;
        };
        entries
            .iter()
            .any(|e| e.released_on_epoch_s > cutoff_secs && version.is_none_or(|v| *v == e.version))
    }
}

#[derive(Clone)]
struct ReleasedPackagesRemoteResource<F> {
    uri: Uri,
    formatter: F,
}

impl<F: PackageNameFormatter> RemoteResourceSpec for ReleasedPackagesRemoteResource<F> {
    type Payload = Vec<ReleasedPackageData>;
    type State = ReleasedPackagesTrie<F>;

    fn refresh_interval(&self) -> Duration {
        Duration::from_mins(10)
    }

    fn build_request(&self) -> Result<Request, BoxError> {
        Request::builder()
            .uri(self.uri.clone())
            .body(Body::empty())
            .context("build package list http request")
    }

    fn build_state(&self, payload: Self::Payload) -> Result<Self::State, BoxError> {
        let now_secs = (rama::utils::time::now_unix_ms()) / 1000;
        Ok(trie_from_released_packages_list(
            payload,
            now_secs,
            &self.formatter,
        ))
    }
}

fn trie_from_released_packages_list<F: PackageNameFormatter>(
    list: Vec<ReleasedPackageData>,
    now_secs: i64,
    formatter: &F,
) -> ReleasedPackagesTrie<F> {
    let cutoff = now_secs.saturating_sub(MAX_ENTRY_AGE_SECS);
    let mut trie = ReleasedPackagesTrie::<F>::new();
    for item in list {
        if item.released_on < cutoff {
            continue;
        }
        let key = formatter.format_package_name(&item.package_name);
        let entry = ReleasedEntry {
            version: item.version,
            released_on_epoch_s: item.released_on,
        };
        match trie.get_mut(&key) {
            Some(entries) => entries.push(entry),
            None => {
                let _previous = trie.insert(key, vec![entry]);
                debug_assert!(
                    _previous.is_none(),
                    "trie::get_mut should have returned result if it already existed!"
                );
            }
        }
    }
    trie
}

/// Deserialized from JSON
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasedPackageData {
    pub package_name: String,
    pub version: PackageVersion,
    pub released_on: i64,
}

#[allow(type_alias_bounds)]
pub type ReleasedPackagesTrie<F: PackageNameFormatter> = Trie<F::PackageName, Vec<ReleasedEntry>>;

/// Stored in the trie (version + timestamp; package_name is the key)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedEntry {
    pub version: PackageVersion,
    pub released_on_epoch_s: i64,
}

#[cfg(test)]
#[path = "released_packages_list_tests.rs"]
mod tests;
