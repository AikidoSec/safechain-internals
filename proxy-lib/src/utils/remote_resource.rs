use std::{fmt, ops::Deref, sync::Arc, time::Duration};

use arc_swap::{ArcSwap, Guard};

use rama::{
    Service,
    error::{BoxError, ErrorContext, ErrorExt as _, extra::OpaqueError},
    graceful::ShutdownGuard,
    http::{BodyExtractExt, Request, Response, StatusCode, header::IF_NONE_MATCH},
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::{sync::Notify, time::Instant};

use crate::{storage::SyncCompactDataStorage, utils::uri::uri_to_filename};

pub(crate) trait RemoteResourceSpec: Send + Sync + 'static {
    type Payload: Serialize + DeserializeOwned + Clone + Send + Sync + 'static;
    type State: Default + Send + Sync + 'static;

    fn refresh_interval(&self) -> Duration;

    /// Build the base outbound request for fetching this remote resource.
    ///
    /// The helper may augment this request before sending, such as by adding
    /// cache-validation headers like `If-None-Match`.
    fn build_request(&self) -> Result<Request, BoxError>;

    fn build_state(&self, payload: Self::Payload) -> Result<Arc<Self::State>, BoxError>;
}

impl<T: RemoteResourceSpec> RemoteResourceSpec for Arc<T> {
    type Payload = T::Payload;
    type State = T::State;

    #[inline(always)]
    fn refresh_interval(&self) -> Duration {
        (**self).refresh_interval()
    }

    #[inline(always)]
    fn build_request(&self) -> Result<Request, BoxError> {
        (**self).build_request()
    }

    #[inline(always)]
    fn build_state(&self, payload: Self::Payload) -> Result<Arc<Self::State>, BoxError> {
        (**self).build_state(payload)
    }
}

pub(crate) struct RemoteResource<T> {
    state: Arc<ArcSwap<T>>,
}

impl<T> Clone for RemoteResource<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<T> fmt::Debug for RemoteResource<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteResource").finish()
    }
}

impl<T> RemoteResource<T> {
    #[cfg(test)]
    pub(crate) fn from_state(state: T) -> Self {
        Self {
            state: Arc::new(ArcSwap::new(Arc::new(state))),
        }
    }

    #[inline(always)]
    pub(crate) fn get(&self) -> RemoteResourceStateRef<T> {
        RemoteResourceStateRef(self.state.load())
    }
}

pub(crate) struct RemoteResourceStateRef<T>(Guard<Arc<T>>);

impl<T> Deref for RemoteResourceStateRef<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RefreshHandle {
    notify: Arc<Notify>,
}

impl RefreshHandle {
    pub(crate) fn trigger_refresh(&self) {
        self.notify.notify_one();
    }
}

pub(crate) async fn try_new<S, C>(
    guard: ShutdownGuard,
    storage: SyncCompactDataStorage,
    client: C,
    spec: S,
) -> Result<(RemoteResource<S::State>, RefreshHandle), BoxError>
where
    S: RemoteResourceSpec + Clone,
    C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
{
    let uri = spec
        .build_request()
        .context("build initial request for remote resource")?
        .uri()
        .clone();
    let filename = uri_to_filename(&uri);

    let (initial_state, e_tag) =
        match load_cached_state(storage.clone(), filename.clone(), spec.clone()).await {
            Ok(Some(cached_info)) => {
                tracing::debug!(
                    "create new remote resource (uri: {}) with cached state",
                    uri
                );
                cached_info
            }
            Ok(None) => {
                tracing::debug!(
                    "no cached remote resource found for endpoint (uri: {}); download fresh state",
                    uri
                );

                #[cfg(not(any(
                    not(feature = "apple-networkextension"),
                    feature = "test-utils",
                    test
                )))]
                {
                    Default::default()
                }

                #[cfg(any(not(feature = "apple-networkextension"), feature = "test-utils", test))]
                {
                    fetch_and_build_state(
                        storage.clone(),
                        filename.clone(),
                        client.clone(),
                        spec.clone(),
                        None,
                    )
                    .await
                    .context("download new remote resource state")
                    .with_context_field("uri", || uri.clone())?
                    .context("new remote resource state not available")?
                }
            }
            Err(err) => {
                tracing::warn!(
                    "failed to load cached remote resource for endpoint (uri: {}); err = {err}",
                    uri
                );

                #[cfg(not(any(
                    not(feature = "apple-networkextension"),
                    feature = "test-utils",
                    test
                )))]
                {
                    Default::default()
                }

                #[cfg(any(not(feature = "apple-networkextension"), feature = "test-utils", test))]
                {
                    fetch_and_build_state(
                        storage.clone(),
                        filename.clone(),
                        client.clone(),
                        spec.clone(),
                        None,
                    )
                    .await
                    .context("download new remote resource state")
                    .with_context_field("uri", || uri.clone())?
                    .context("new remote resource state not available")?
                }
            }
        };

    let state = Arc::new(ArcSwap::new(initial_state));
    let refresh_handle = RefreshHandle {
        notify: Arc::new(Notify::new()),
    };

    tokio::spawn(update_loop(
        guard,
        client,
        storage,
        uri,
        filename,
        spec,
        e_tag,
        state.clone(),
        refresh_handle.notify.clone(),
    ));

    Ok((RemoteResource { state }, refresh_handle))
}

#[allow(clippy::too_many_arguments)]
async fn update_loop<S, C>(
    guard: ShutdownGuard,
    client: C,
    storage: SyncCompactDataStorage,
    uri: rama::http::Uri,
    filename: ArcStr,
    spec: S,
    e_tag: Option<ArcStr>,
    shared_state: Arc<ArcSwap<S::State>>,
    refresh_notify: Arc<Notify>,
) where
    S: RemoteResourceSpec + Clone,
    C: Service<Request, Output = Response, Error = OpaqueError> + Clone + Send + 'static,
{
    tracing::debug!(
        "remote resource (uri = {}), update loop task up and running",
        uri
    );

    let mut sleep_for = if e_tag.is_some() {
        with_jitter(spec.refresh_interval())
    } else {
        Duration::ZERO
    };
    let mut latest_e_tag = e_tag;

    loop {
        tracing::debug!("remote resource (uri = {uri}), sleep for: {sleep_for:?}");

        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {
                tracing::debug!("remote resource (uri = {uri}), task woke up");
            },
            _ = refresh_notify.notified() => {
                tracing::debug!("remote resource (uri = {uri}), task got nodified early via trigger");
            },
            _ = guard.cancelled() => {
                tracing::debug!("remote resource (uri = {uri}), guard cancelled; exit");
                return;
            }
        }

        match fetch_and_build_state(
            storage.clone(),
            filename.clone(),
            client.clone(),
            spec.clone(),
            latest_e_tag.as_deref(),
        )
        .await
        {
            Ok(Some((fresh_state, fresh_e_tag))) => {
                tracing::debug!("remote resource (uri = {uri}), state updated");
                shared_state.store(fresh_state);
                sleep_for = with_jitter(spec.refresh_interval());
                latest_e_tag = fresh_e_tag;
            }
            Ok(None) => {
                tracing::debug!(
                    "remote resource (uri = {uri}), state was unmodified, preserve current one"
                );
                sleep_for = with_jitter(spec.refresh_interval());
            }
            Err(err) => {
                tracing::error!(
                    "remote resource (uri = {uri}), failed to update (err = {err}), try again in shorter interval...",
                );
                let fail_interval = Duration::from_secs(std::cmp::max(sleep_for.as_secs() / 2, 60));
                sleep_for = with_jitter(fail_interval);
            }
        }
    }
}

async fn fetch_and_build_state<S, C>(
    storage: SyncCompactDataStorage,
    filename: ArcStr,
    client: C,
    spec: S,
    previous_e_tag: Option<&str>,
) -> Result<Option<(Arc<S::State>, Option<ArcStr>)>, BoxError>
where
    S: RemoteResourceSpec + Clone,
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    let Some((payload, new_e_tag)) = fetch_payload(spec.clone(), client, previous_e_tag).await?
    else {
        return Ok(None);
    };

    spawn_payload_caching_task(storage, filename, payload.clone(), new_e_tag.clone());

    let state = spec
        .build_state(payload)
        .context("build remote resource state")?;

    Ok(Some((state, new_e_tag)))
}

async fn fetch_payload<S, C>(
    spec: S,
    client: C,
    previous_e_tag: Option<&str>,
) -> Result<Option<(S::Payload, Option<ArcStr>)>, BoxError>
where
    S: RemoteResourceSpec,
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    let mut req = spec
        .build_request()
        .context("build outbound request for remote resource")?;
    let uri = req.uri().clone();

    if let Some(e_tag) = previous_e_tag {
        req.headers_mut().insert(
            IF_NONE_MATCH,
            e_tag
                .try_into()
                .context("convert cached etag into if-none-match header value")?,
        );
    }

    let start = Instant::now();
    let resp = client
        .serve(req)
        .await
        .context("fetch remote resource from remote endpoint")
        .context_debug_field("tt", start.elapsed())
        .with_context_field("uri", || uri.clone())?;

    if resp.status() == StatusCode::NOT_MODIFIED {
        tracing::debug!(
            "remote resource endpoint '{uri}' reported state not modified; (tt: {:?})",
            start.elapsed()
        );
        return Ok(None);
    }

    if !resp.status().is_success() {
        let http_status_code = resp.status();
        let maybe_error_msg = resp.try_into_string().await.unwrap_or_default();
        return Err(
            BoxError::from("failed to download remote resource from remote endpoint")
                .with_context_field("uri", || uri.clone())
                .context_field("status", http_status_code)
                .context_field("message", maybe_error_msg),
        );
    }

    let e_tag: Option<ArcStr> = resp
        .headers()
        .get("etag")
        .and_then(|v| v.as_bytes().try_into().ok());

    let payload: S::Payload = resp
        .try_into_json()
        .await
        .context("collect and json-decode remote resource response payload")
        .with_context_field("uri", || uri.clone())
        .with_context_debug_field("tt", || start.elapsed())?;

    tracing::debug!(
        "fetched and decoded remote resource from '{}' (tt: {:?})",
        uri,
        start.elapsed(),
    );

    Ok(Some((payload, e_tag)))
}

async fn load_cached_state<S>(
    storage: SyncCompactDataStorage,
    filename: ArcStr,
    spec: S,
) -> Result<Option<(Arc<S::State>, Option<ArcStr>)>, BoxError>
where
    S: RemoteResourceSpec,
{
    tokio::task::spawn_blocking(move || {
        let cached: Option<CachedRemoteResource<S::Payload>> =
            storage.load(&filename).context("storage failure")?;

        let Some(cached) = cached else {
            return Ok(None);
        };

        let state = spec
            .build_state(cached.payload)
            .context("build remote resource state from cached payload")?;

        Ok(Some((state, cached.e_tag)))
    })
    .await
    .context("wait for blocking task to load cached remote resource")?
}

fn spawn_payload_caching_task<T>(
    storage: SyncCompactDataStorage,
    filename: ArcStr,
    payload: T,
    e_tag: Option<ArcStr>,
) where
    T: Serialize + Send + Sync + 'static,
{
    tokio::task::spawn_blocking(move || {
        if let Err(err) = storage.store(
            &filename,
            &CachedRemoteResource {
                e_tag: e_tag.clone(),
                payload,
            },
        ) {
            tracing::error!("failed to backup downloaded remote resource @ '{filename}': {err}")
        }
    });
}

fn with_jitter(refresh: Duration) -> Duration {
    let max_jitter = std::cmp::min(refresh, Duration::from_secs(60));
    let jitter_secs = rand::RngExt::random_range(&mut rand::rng(), 0.0..=max_jitter.as_secs_f64());
    refresh + Duration::from_secs_f64(jitter_secs)
}

#[derive(Serialize, serde::Deserialize)]
struct CachedRemoteResource<T> {
    pub e_tag: Option<ArcStr>,
    pub payload: T,
}
