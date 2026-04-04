use std::{fmt, marker::PhantomData, sync::Arc, time::Duration};

use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{Body, Request, Response, Uri},
};

use radix_trie::Trie;
use serde::{Deserialize, Serialize};

use crate::{
    package::{name_formatter::PackageName, version::PackageVersion},
    storage::SyncCompactDataStorage,
    utils::{
        remote_resource::{self, RemoteResource, RemoteResourceSpec},
        time::{SystemDuration, SystemTimestampMilliseconds},
    },
};

/// How long to keep entries in the trie.
/// Entries older than this are irrelevant to the configured blocking window.
const MAX_ENTRY_AGE: SystemDuration = SystemDuration::days(7);

pub struct RemoteReleasedPackagesList<K> {
    trie: RemoteResource<ReleasedPackagesTrie<K>>,
}

impl<K> Clone for RemoteReleasedPackagesList<K> {
    fn clone(&self) -> Self {
        Self {
            trie: self.trie.clone(),
        }
    }
}

impl<K> fmt::Debug for RemoteReleasedPackagesList<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteReleasedPackagesList").finish()
    }
}

impl<K> RemoteReleasedPackagesList<K> {
    pub async fn try_new<C>(
        guard: ShutdownGuard,
        uri: Uri,
        sync_storage: SyncCompactDataStorage,
        client: C,
    ) -> Result<Self, BoxError>
    where
        K: PackageName + radix_trie::TrieKey + Send + Sync + 'static,
        C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
    {
        let (trie, _refresh_handle) = remote_resource::try_new(
            guard,
            sync_storage,
            client,
            Arc::new(ReleasedPackagesRemoteResource::<K> {
                uri,
                _phantom: PhantomData,
            }),
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
        package_name: &K,
        version: Option<&PackageVersion>,
        cutoff_ts: SystemTimestampMilliseconds,
    ) -> bool
    where
        K: radix_trie::TrieKey,
    {
        let state_ref = self.trie.get();
        let Some(entries) = state_ref.get(package_name) else {
            return false;
        };
        entries
            .iter()
            .any(|e| e.released_on > cutoff_ts && version.is_none_or(|v| *v == e.version))
    }
}

struct ReleasedPackagesRemoteResource<K> {
    uri: Uri,
    _phantom: PhantomData<K>,
}

impl<K> RemoteResourceSpec for ReleasedPackagesRemoteResource<K>
where
    K: PackageName + radix_trie::TrieKey + Send + Sync + 'static,
{
    type Payload = Vec<ReleasedPackageData>;
    type State = ReleasedPackagesTrie<K>;

    fn refresh_interval(&self) -> Duration {
        Duration::from_mins(10)
    }

    fn build_request(&self) -> Result<Request, BoxError> {
        Request::builder()
            .uri(self.uri.clone())
            .body(Body::empty())
            .context("build package list http request")
    }

    fn build_state(&self, payload: Self::Payload) -> Result<Arc<Self::State>, BoxError> {
        let now_ts = SystemTimestampMilliseconds::now();
        Ok(Arc::new(trie_from_released_packages_list(payload, now_ts)))
    }
}

fn trie_from_released_packages_list<K: PackageName + radix_trie::TrieKey>(
    list: Vec<ReleasedPackageData>,
    now_ts: SystemTimestampMilliseconds,
) -> ReleasedPackagesTrie<K> {
    let cutoff = now_ts - MAX_ENTRY_AGE;
    let mut trie = ReleasedPackagesTrie::<K>::new();
    for item in list {
        if item.released_on < cutoff {
            continue;
        }
        let key = K::normalize(&item.package_name);
        let entry = ReleasedEntry {
            version: item.version,
            released_on: item.released_on,
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
    #[serde(with = "crate::utils::time::system_time_serde_seconds")]
    pub released_on: SystemTimestampMilliseconds,
}

pub type ReleasedPackagesTrie<K> = Trie<K, Vec<ReleasedEntry>>;

/// Stored in the trie (version + timestamp; package_name is the key)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedEntry {
    pub version: PackageVersion,
    pub released_on: SystemTimestampMilliseconds,
}

#[cfg(test)]
#[path = "released_packages_list_tests.rs"]
mod tests;
