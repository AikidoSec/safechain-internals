//! XPC routes for driving MITM CA generation + commit from the container app.
//!
//! Two routes, deliberately small and explicit:
//!
//! - `generateCaCrt:withReply:` — the sysext mints a fresh CA in memory and
//!   parks it in [`crate::state::LiveCa::pending`]. The active TLS relay is
//!   left alone, but the hijack endpoint immediately starts serving the new
//!   PEM so callers can fetch the next cert and install trust for it. The
//!   reply carries the new DER (base64) so callers that talk XPC directly
//!   don't have to fetch from hijack.
//! - `commitCaCrt:withReply:` — fails if no pending CA is parked. Otherwise
//!   persists the pending CA in the SE-encrypted system keychain (fail-fast
//!   if persist fails); only after persist succeeds is the active relay
//!   atomically swapped. The reply carries the previous active CA's DER
//!   (base64), so callers can drop its trust.
//!
//! There is intentionally **no** install/uninstall route here: the container
//! app handles trust storage outside of XPC. There is also no "delete CA"
//! route — that lives entirely on the container side because the relevant
//! keychain entries (legacy data-protection + System Keychain items) are
//! addressable from the user-side process.
//!
//! Pending state lives only in memory. If the sysext restarts before commit,
//! the caller has to re-issue `generate-ca-crt` — see [`crate::state`] for
//! the rationale.
//!
//! The listener is pinned to the container app's exact code identity via
//! [`PeerSecurityRequirement::CodeSigning`]: exact bundle identifier and
//! exact Apple Developer team. We refuse to bind when either value is
//! missing from the engine config — failing closed is safer than exposing
//! the routes to any other process on the host.

use std::sync::Arc;

use base64::Engine as _;
use rama::{
    bytes::Bytes,
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    net::apple::xpc::{
        PeerSecurityRequirement, XpcListener, XpcListenerConfig, XpcMessageRouter, XpcServer,
    },
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
    utils::str::arcstr::ArcStr,
};
use serde::{Deserialize, Serialize};

use crate::state::{ActiveCa, LiveCa, PendingCa, SharedCaState};

#[derive(Debug, Default, Deserialize)]
struct EmptyRequest {}

/// Reply for `generateCaCrt:withReply:` and `commitCaCrt:withReply:`.
#[derive(Debug, Serialize)]
struct CaCommandReply {
    ok: bool,
    error: Option<String>,
    /// `generateCaCrt`: DER of the freshly minted (pending) CA.
    /// `commitCaCrt`: DER of the previous active CA, if any.
    cert_der_b64: Option<String>,
}

impl CaCommandReply {
    fn ok_with_cert(cert_der: &[u8]) -> Self {
        Self {
            ok: true,
            error: None,
            cert_der_b64: Some(base64::engine::general_purpose::STANDARD.encode(cert_der)),
        }
    }

    fn ok_without_cert() -> Self {
        Self {
            ok: true,
            error: None,
            cert_der_b64: None,
        }
    }

    fn err(err: &BoxError) -> Self {
        Self {
            ok: false,
            error: Some(format!("{err:#}")),
            cert_der_b64: None,
        }
    }
}

/// Spawn the sysext's XPC listener.
///
/// `service_name` is the value declared as `NEMachServiceName` in the
/// extension's `Info.plist`, forwarded by the container app through the
/// opaque engine config. `container_signing_identifier` is the container
/// app's `Bundle.main.bundleIdentifier`; `container_team_identifier` is the
/// Apple Developer team identifier derived by the container app.
///
/// Any required argument missing or empty is a fail-closed condition: the
/// listener is **not** bound, which means `generate-ca-crt` /
/// `commit-ca-crt` calls from the container will fail loudly.
pub(crate) fn spawn(
    service_name: Option<ArcStr>,
    container_signing_identifier: Option<ArcStr>,
    container_team_identifier: Option<ArcStr>,
    state: SharedCaState,
    executor: Executor,
) -> Result<(), BoxError> {
    let service_name =
        service_name
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| -> BoxError {
                tracing::error!(
                    "xpc server: `xpc_service_name` is missing or empty in opaque engine config; \
                 refusing to bind XPC listener (fail-closed)."
                );
                OpaqueError::from_static_str("xpc server: missing xpc_service_name (fail-closed)")
                    .into_box_error()
            })?;

    let signing_identifier = container_signing_identifier
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| -> BoxError {
            tracing::error!(
                "xpc server: `container_signing_identifier` is missing or empty in opaque \
                 engine config; refusing to bind XPC listener (fail-closed). Set it from \
                 the container app's `Bundle.main.bundleIdentifier`."
            );
            OpaqueError::from_static_str(
                "xpc server: missing container_signing_identifier (fail-closed)",
            )
            .into_box_error()
        })?;

    let team_identifier = container_team_identifier
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| -> BoxError {
            tracing::error!(
                "xpc server: `container_team_identifier` is missing or empty in opaque \
                 engine config; refusing to bind XPC listener (fail-closed)."
            );
            OpaqueError::from_static_str(
                "xpc server: missing container_team_identifier (fail-closed)",
            )
            .into_box_error()
        })?;

    let requirement =
        build_peer_code_signing_requirement(signing_identifier.as_str(), team_identifier.as_str())?;

    tracing::info!(
        %service_name,
        %signing_identifier,
        %team_identifier,
        "xpc server: start config+spawn (peer pinned to exact team + bundle identifier)"
    );

    let config = XpcListenerConfig::new(service_name.clone())
        .with_peer_requirement(PeerSecurityRequirement::CodeSigning(requirement));

    let router = XpcMessageRouter::new()
        .with_typed_route::<EmptyRequest, CaCommandReply, _>(
            "generateCaCrt:withReply:",
            service_fn({
                let state = state.clone();
                move |_req: EmptyRequest| {
                    let state = state.clone();
                    async move {
                        tracing::info!("xpc server: generateCaCrt invoked");
                        let reply = match generate_into_pending(&state) {
                            Ok(der) => {
                                tracing::info!(
                                    der_len = der.len(),
                                    "xpc server: generateCaCrt succeeded — pending CA parked"
                                );
                                CaCommandReply::ok_with_cert(&der)
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "xpc server: generateCaCrt failed");
                                CaCommandReply::err(&err)
                            }
                        };
                        Ok::<_, BoxError>(reply)
                    }
                }
            }),
        )
        .with_typed_route::<EmptyRequest, CaCommandReply, _>(
            "commitCaCrt:withReply:",
            service_fn({
                let state = state;
                move |_req: EmptyRequest| {
                    let state = state.clone();
                    async move {
                        tracing::info!("xpc server: commitCaCrt invoked");
                        let reply = match commit_pending(&state) {
                            Ok(previous_der) => {
                                tracing::info!(
                                    previous_present = previous_der.is_some(),
                                    "xpc server: commitCaCrt succeeded — active CA swapped"
                                );
                                match previous_der {
                                    Some(der) => CaCommandReply::ok_with_cert(&der),
                                    None => CaCommandReply::ok_without_cert(),
                                }
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "xpc server: commitCaCrt failed");
                                CaCommandReply::err(&err)
                            }
                        };
                        Ok::<_, BoxError>(reply)
                    }
                }
            }),
        );

    let server = XpcServer::new(router);

    let listener = XpcListener::bind(config)
        .context("bind aikido L4 sysext xpc listener")
        .with_context_debug_field("serviceName", || service_name.clone())?;

    let exec_for_loop = executor.clone();
    executor.spawn_cancellable_task(async move {
        tracing::info!(%service_name, "xpc server: listener active");
        if let Err(err) = server.serve_listener(listener, exec_for_loop).await {
            tracing::error!(%service_name, %err, "xpc server: listener exited with error");
        }
    });

    Ok(())
}

fn generate_into_pending(state: &SharedCaState) -> Result<Bytes, BoxError> {
    let pending = crate::tls::generate_pending_ca().context("generate pending MITM CA")?;
    let der = pending.cert_der.clone();

    state.rcu(|cur| LiveCa {
        active: cur.active.clone(),
        pending: Some(Arc::new(pending.clone())),
    });

    Ok(der)
}

fn commit_pending(state: &SharedCaState) -> Result<Option<Bytes>, BoxError> {
    let cur = state.load_full();
    let Some(pending) = cur.pending.as_ref().cloned() else {
        return Err(OpaqueError::from_static_str(
            "no pending MITM CA to commit; call generateCaCrt first",
        )
        .into_box_error());
    };

    crate::tls::persist_pending_ca(&pending).context("persist pending MITM CA")?;

    let new_active = build_active_from_pending(&pending);
    Ok(promote_committed_pending(state, &pending, new_active))
}

fn promote_committed_pending(
    state: &SharedCaState,
    committed_pending: &Arc<PendingCa>,
    new_active: Arc<ActiveCa>,
) -> Option<Bytes> {
    let mut previous_der: Option<Bytes> = None;
    state.rcu(|live| {
        // Hold on to whatever was active when this rcu closure ran. rcu may
        // re-run, so we capture every time and keep the latest one — by the
        // time the swap actually lands, this will be the cert we displaced.
        previous_der = Some(live.active.cert_der.clone());
        // Preserve a newer pending CA that may have been generated while this
        // commit was persisting the older one. Only clear `pending` when the
        // slot still points at the CA being promoted.
        let pending = match live.pending.as_ref() {
            Some(current) if Arc::ptr_eq(current, committed_pending) => None,
            Some(current) => Some(current.clone()),
            None => None,
        };
        LiveCa {
            active: new_active.clone(),
            pending,
        }
    });
    previous_der
}

fn build_active_from_pending(pending: &PendingCa) -> Arc<ActiveCa> {
    Arc::new(ActiveCa {
        relay: rama::tls::boring::proxy::TlsMitmRelay::new_cached_in_memory(
            pending.cert.clone(),
            pending.key.clone(),
        ),
        cert_pem: pending.cert_pem.clone(),
        cert_der: pending.cert_der.clone(),
    })
}

fn build_peer_code_signing_requirement(
    signing_identifier: &str,
    team_identifier: &str,
) -> Result<ArcStr, BoxError> {
    let signing_identifier =
        sanitize_requirement_atom("container_signing_identifier", signing_identifier)?;
    let team_identifier = sanitize_requirement_atom("container_team_identifier", team_identifier)?;
    Ok(ArcStr::from(format!(
        "anchor apple generic and certificate leaf[subject.OU] = \"{team_identifier}\" and identifier \"{signing_identifier}\""
    )))
}

fn sanitize_requirement_atom<'a>(field: &'static str, value: &'a str) -> Result<&'a str, BoxError> {
    if value.contains('"') || value.contains('\\') {
        return Err(OpaqueError::from_static_str(
            "xpc server: invalid code signing requirement component",
        )
        .context_field("field", field));
    }
    Ok(value)
}

#[cfg(test)]
#[path = "xpc_server_tests.rs"]
mod tests;
