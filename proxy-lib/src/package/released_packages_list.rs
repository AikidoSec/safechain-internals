use std::{fmt, sync::Arc, time::Duration};

use rama::{
    Service,
    error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{
        BodyExtractExt, Request, Response, StatusCode, Uri, service::client::HttpClientExt as _,
    },
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};

use arc_swap::ArcSwap;
use radix_trie::Trie;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{storage::SyncCompactDataStorage, utils::uri::uri_to_filename};

/// How long to keep entries in the trie (7 days).
/// Entries older than this are irrelevant to the 24h blocking window.
const MAX_ENTRY_AGE_SECS: u64 = 7 * 24 * 3600;

type ReleasedPackagesTrie = Trie<String, Vec<ReleasedEntry>>;

#[derive(Clone)]
pub struct RemoteReleasedPackagesList {
    trie: Arc<ArcSwap<ReleasedPackagesTrie>>,
}

impl fmt::Debug for RemoteReleasedPackagesList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteReleasedPackagesList").finish()
    }
}

impl RemoteReleasedPackagesList {
    pub async fn try_new<C>(
        guard: ShutdownGuard,
        uri: Uri,
        sync_storage: SyncCompactDataStorage,
        client: C,
    ) -> Result<Self, BoxError>
    where
        C: Service<Request, Output = Response, Error = OpaqueError>,
    {
        let filename = uri_to_filename(&uri);
        let refresh_interval = Duration::from_mins(10);
        let client = RemoteReleasedPackagesListClient {
            uri,
            filename,
            refresh_interval,
            sync_storage,
            client,
        };

        let (trie, e_tag) = match client.load_cached_trie().await {
            Ok(Some(cached_info)) => {
                tracing::debug!(
                    "create new remote released packages list (uri: {}) with cached trie",
                    client.uri
                );
                cached_info
            }
            Ok(None) => {
                tracing::debug!(
                    "no cached released packages list found for remote endpoint (uri: {})",
                    client.uri
                );
                #[cfg(feature = "apple-networkextension")]
                {
                    Default::default()
                }
                #[cfg(not(feature = "apple-networkextension"))]
                {
                    client
                        .download_trie(None)
                        .await
                        .context("download new released packages list")?
                        .context("new released packages list not available")?
                }
            }
            Err(err) => {
                tracing::warn!(
                    "failed to load cached released packages list for remote endpoint (uri: {}); err = {err}",
                    client.uri
                );
                #[cfg(feature = "apple-networkextension")]
                {
                    Default::default()
                }
                #[cfg(not(feature = "apple-networkextension"))]
                {
                    client
                        .download_trie(None)
                        .await
                        .context("download new released packages list")?
                        .context("new released packages list not available")?
                }
            }
        };

        let shared_trie = Arc::new(ArcSwap::new(Arc::new(trie)));

        tokio::spawn(remote_released_packages_update_loop(
            guard,
            client,
            e_tag,
            shared_trie.clone(),
        ));

        Ok(Self { trie: shared_trie })
    }

    /// Returns true if the package was released recently (after `cutoff_secs`).
    ///
    /// - `version = Some(v)`: only the specific version must be recent
    /// - `version = None`: true if ANY version of the package is recent
    pub fn is_recently_released(
        &self,
        package_name: &str,
        version: Option<&str>,
        cutoff_secs: u64,
    ) -> bool {
        let key = package_name.trim().to_ascii_lowercase();
        let guard = self.trie.load();
        let Some(entries) = guard.get(key.as_str()) else {
            return false;
        };
        entries.iter().any(|e| {
            e.released_on > cutoff_secs
                && version.is_none_or(|v| v.trim().to_ascii_lowercase() == e.version)
        })
    }
}

struct RemoteReleasedPackagesListClient<C> {
    uri: Uri,
    filename: ArcStr,
    refresh_interval: Duration,
    sync_storage: SyncCompactDataStorage,
    client: C,
}

impl<C> RemoteReleasedPackagesListClient<C>
where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    async fn download_trie(
        &self,
        e_tag: Option<&str>,
    ) -> Result<Option<(ReleasedPackagesTrie, Option<ArcStr>)>, BoxError> {
        let Some((list, new_e_tag)) = self.fetch_remote_list_and_e_tag(e_tag).await? else {
            return Ok(None);
        };

        self.spawn_caching_task(list.clone(), new_e_tag.clone());

        let now_secs = (rama::utils::time::now_unix_ms() as u64) / 1000;
        let trie = trie_from_released_packages_list(list, now_secs);

        tracing::debug!(
            "released packages trie refreshed with link to remote endpoint '{}'",
            self.uri,
        );

        Ok(Some((trie, new_e_tag)))
    }

    async fn fetch_remote_list_and_e_tag(
        &self,
        previous_e_tag: Option<&str>,
    ) -> Result<Option<(Vec<ReleasedPackageData>, Option<ArcStr>)>, BoxError> {
        let start = Instant::now();

        let req_builder = self.client.get(self.uri.clone());
        let req_builder = if let Some(e_tag) = previous_e_tag {
            req_builder.header("if-none-match", e_tag)
        } else {
            req_builder
        };

        let resp = req_builder
            .send()
            .await
            .context("fetch released packages list from remote endpoint")
            .context_debug_field("tt", start.elapsed())
            .with_context_field("uri", || self.uri.clone())?;

        if resp.status() == StatusCode::NOT_MODIFIED {
            tracing::debug!(
                "released packages list endpoint '{}' reported list not modified; (tt: {:?})",
                self.uri,
                start.elapsed()
            );
            return Ok(None);
        }

        if !resp.status().is_success() {
            let http_status_code = resp.status();
            let maybe_error_msg = resp.try_into_string().await.unwrap_or_default();
            return Err(BoxError::from(
                "failed to download released packages list from remote endpoint",
            )
            .with_context_field("uri", || self.uri.clone())
            .context_field("status", http_status_code)
            .context_field("message", maybe_error_msg));
        }

        let e_tag: Option<ArcStr> = resp
            .headers()
            .get("etag")
            .and_then(|v| v.as_bytes().try_into().ok());

        let list: Vec<ReleasedPackageData> = resp
            .try_into_json()
            .await
            .context(
                "collect and json-decode released packages list response payload from remote endpoint",
            )
            .with_context_field("uri", || self.uri.clone())
            .with_context_debug_field("tt", || start.elapsed())?;

        tracing::debug!(
            "fetched and decoded released packages list from remote endpoint '{}', with {} entries (tt: {:?})",
            self.uri,
            list.len(),
            start.elapsed(),
        );

        Ok(Some((list, e_tag)))
    }

    fn spawn_caching_task(&self, list: Vec<ReleasedPackageData>, e_tag: Option<ArcStr>) {
        let storage = self.sync_storage.clone();
        let filename = self.filename.clone();

        tokio::task::spawn_blocking(move || {
            if let Err(err) = storage.store(
                &filename,
                &CachedReleasedPackagesList {
                    e_tag: e_tag.clone(),
                    list,
                },
            ) {
                tracing::error!(
                    "failed to backup downloaded released packages list @ '{filename}': {err}"
                )
            }
        });
    }

    async fn load_cached_trie(
        &self,
    ) -> Result<Option<(ReleasedPackagesTrie, Option<ArcStr>)>, BoxError> {
        tokio::task::spawn_blocking({
            let storage = self.sync_storage.clone();
            let filename = self.filename.clone();
            move || load_cached_trie_sync_inner(storage, filename)
        })
        .await
        .context("wait for blocking task to use cached released packages list")
        .with_context_field("uri", || self.uri.clone())?
    }
}

fn load_cached_trie_sync_inner(
    storage: SyncCompactDataStorage,
    filename: ArcStr,
) -> Result<Option<(ReleasedPackagesTrie, Option<ArcStr>)>, BoxError> {
    let cached: Option<CachedReleasedPackagesList> =
        storage.load(&filename).context("storage failure")?;

    let Some(cached) = cached else {
        return Ok(None);
    };

    let now_secs = (rama::utils::time::now_unix_ms() as u64) / 1000;
    let trie = trie_from_released_packages_list(cached.list, now_secs);

    Ok(Some((trie, cached.e_tag)))
}

async fn remote_released_packages_update_loop<C>(
    guard: ShutdownGuard,
    client: RemoteReleasedPackagesListClient<C>,
    e_tag: Option<ArcStr>,
    shared_trie: Arc<ArcSwap<ReleasedPackagesTrie>>,
) where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    tracing::debug!(
        "remote released packages list (uri = {}), update loop task up and running",
        client.uri
    );

    let mut sleep_for = if e_tag.is_some() {
        with_jitter(client.refresh_interval)
    } else {
        Duration::ZERO
    };

    let mut latest_e_tag = e_tag;

    loop {
        tracing::debug!(
            "remote released packages list (uri = {}), sleep for: {sleep_for:?}",
            client.uri
        );
        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {},
            _ = guard.cancelled() => {
                tracing::debug!(
                    "remote released packages list (uri = {}), guard cancelled; exit",
                    client.uri
                );
                return;
            }
        }

        match client.download_trie(latest_e_tag.as_deref()).await {
            Ok(Some((fresh_trie, fresh_e_tag))) => {
                tracing::debug!(
                    "remote released packages list (uri = {}), trie updated",
                    client.uri
                );
                shared_trie.store(Arc::new(fresh_trie));
                sleep_for = with_jitter(client.refresh_interval);
                latest_e_tag = fresh_e_tag;
            }
            Ok(None) => {
                tracing::debug!("released packages list was unmodified, preserve current one...");
                sleep_for = with_jitter(client.refresh_interval);
            }
            Err(err) => {
                tracing::error!(
                    "remote released packages list (uri = {}), failed to update (err = {err}), try again in shorter interval...",
                    client.uri
                );
                let fail_interval = Duration::from_secs(std::cmp::max(sleep_for.as_secs() / 2, 60));
                sleep_for = with_jitter(fail_interval);
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CachedReleasedPackagesList {
    pub e_tag: Option<ArcStr>,
    pub list: Vec<ReleasedPackageData>,
}

fn with_jitter(refresh: Duration) -> Duration {
    let max_jitter = std::cmp::min(refresh, Duration::from_secs(60));
    let jitter_secs = rand::rng().random_range(0.0..=max_jitter.as_secs_f64());
    refresh + Duration::from_secs_f64(jitter_secs)
}

fn trie_from_released_packages_list(
    list: Vec<ReleasedPackageData>,
    now_secs: u64,
) -> ReleasedPackagesTrie {
    let cutoff = now_secs.saturating_sub(MAX_ENTRY_AGE_SECS);
    let mut trie = ReleasedPackagesTrie::new();
    for item in list {
        if item.released_on < cutoff {
            continue;
        }
        let key = item.package_name.trim().to_ascii_lowercase();
        let entry = ReleasedEntry {
            version: item.version.trim().to_ascii_lowercase(),
            released_on: item.released_on,
        };
        match trie.get_mut(key.as_str()) {
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
    pub version: String,
    pub released_on: u64,
}

/// Stored in the trie (version + timestamp; package_name is the key)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedEntry {
    pub version: String,
    pub released_on: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trie(entries: Vec<ReleasedPackageData>, now_secs: u64) -> ReleasedPackagesTrie {
        trie_from_released_packages_list(entries, now_secs)
    }

    fn make_list(
        package_name: &str,
        version: &str,
        released_on: u64,
    ) -> RemoteReleasedPackagesList {
        let trie = trie_from_released_packages_list(
            vec![ReleasedPackageData {
                package_name: package_name.to_owned(),
                version: version.to_owned(),
                released_on,
            }],
            released_on + 3600, // now = 1h after release
        );
        RemoteReleasedPackagesList {
            trie: Arc::new(ArcSwap::new(Arc::new(trie))),
        }
    }

    #[test]
    fn test_is_recently_released_specific_version_match() {
        // package released 1h ago, cutoff = 2h ago → should be recent
        let released_on = 1_000_000_u64;
        let list = make_list("my-ext", "1.0.0", released_on);
        let cutoff = released_on - 7200; // 2h before release
        assert!(list.is_recently_released("my-ext", Some("1.0.0"), cutoff));
    }

    #[test]
    fn test_is_recently_released_specific_version_no_match_wrong_version() {
        let released_on = 1_000_000_u64;
        let list = make_list("my-ext", "1.0.0", released_on);
        let cutoff = released_on - 7200;
        assert!(!list.is_recently_released("my-ext", Some("2.0.0"), cutoff));
    }

    #[test]
    fn test_is_recently_released_any_version() {
        let released_on = 1_000_000_u64;
        let list = make_list("my-ext", "1.0.0", released_on);
        let cutoff = released_on - 7200;
        assert!(list.is_recently_released("my-ext", None, cutoff));
    }

    #[test]
    fn test_is_recently_released_stale_entry() {
        // released_on is BEFORE the cutoff → not recent
        let released_on = 1_000_000_u64;
        let list = make_list("my-ext", "1.0.0", released_on);
        let cutoff = released_on + 3600; // cutoff is 1h AFTER release
        assert!(!list.is_recently_released("my-ext", Some("1.0.0"), cutoff));
    }

    #[test]
    fn test_is_recently_released_unknown_package() {
        let released_on = 1_000_000_u64;
        let list = make_list("my-ext", "1.0.0", released_on);
        let cutoff = released_on - 7200;
        assert!(!list.is_recently_released("unknown-ext", None, cutoff));
    }

    #[test]
    fn test_trie_filters_old_entries() {
        let now_secs = 1_000_000_u64;
        let cutoff = now_secs.saturating_sub(MAX_ENTRY_AGE_SECS);
        let entries = vec![
            ReleasedPackageData {
                package_name: "old-pkg".to_owned(),
                version: "1.0.0".to_owned(),
                released_on: cutoff - 1, // older than max age
            },
            ReleasedPackageData {
                package_name: "new-pkg".to_owned(),
                version: "1.0.0".to_owned(),
                released_on: cutoff + 1, // within max age
            },
        ];
        let trie = make_trie(entries, now_secs);
        assert!(trie.get("old-pkg").is_none());
        assert!(trie.get("new-pkg").is_some());
    }

    #[test]
    fn test_is_recently_released_case_insensitive() {
        let released_on = 1_000_000_u64;
        let list = make_list("My-Ext", "1.0.0", released_on);
        let cutoff = released_on - 7200;
        assert!(list.is_recently_released("MY-EXT", Some("1.0.0"), cutoff));
    }
}
