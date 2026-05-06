//! Shared, atomically swappable MITM CA state for the L4 transparent proxy
//! sysext.
//!
//! The active CA (the one used for real TLS interception) and any
//! freshly-minted pending CA live together inside a single `ArcSwap<LiveCa>`,
//! so we can roll either piece forward without disrupting in-flight flows.
//!
//! Lifecycle:
//!
//! - **Boot.** [`tls::load_or_create_active_ca`] returns the active pair —
//!   loaded from the SE-encrypted system keychain, or freshly minted +
//!   persisted on first boot, or (deprecated) lifted from opaque config when
//!   a legacy CA is forwarded by the container app.
//! - **Generate (XPC).** A fresh CA is minted in memory and parked in
//!   [`LiveCa::pending`]. The active relay is untouched, but the hijack
//!   endpoint already serves the pending PEM so callers can fetch the next
//!   cert and install trust for it.
//! - **Commit (XPC).** Pending is persisted to the SE-encrypted system
//!   keychain; only after that succeeds do we rebuild the relay and swap
//!   the active CA. The previous active DER is returned to the caller so
//!   downstream trust stores can drop it.
//!
//! Pending state is in-memory only. If the sysext restarts before commit, the
//! caller has to re-issue `generate-ca-crt`; persisting partially-completed
//! rotations on disk would only buy us trouble.

use std::sync::Arc;

use arc_swap::ArcSwap;
use rama::{
    bytes::Bytes,
    tls::boring::{
        core::{
            pkey::{PKey, Private},
            x509::X509,
        },
        proxy::{
            TlsMitmRelay,
            cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
        },
    },
};

/// `TlsMitmRelay` flavour used by this sysext: in-memory issuer with leaf
/// caching. Matches the original `TcpTlsMitmRelay` alias inside `tcp.rs`.
pub(crate) type AikidoTlsMitmRelay =
    TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>;

/// CA pair currently used for TLS interception.
#[derive(Clone)]
pub(crate) struct ActiveCa {
    pub(crate) relay: AikidoTlsMitmRelay,
    pub(crate) cert_pem: Bytes,
    pub(crate) cert_der: Bytes,
}

/// CA pair minted by `generate-ca-crt` but not yet active. Cloning is cheap
/// because boring's `X509` / `PKey` are reference-counted internally.
#[derive(Clone)]
pub(crate) struct PendingCa {
    pub(crate) cert: X509,
    pub(crate) key: PKey<Private>,
    pub(crate) cert_pem: Bytes,
    pub(crate) cert_der: Bytes,
}

/// Atomically swappable view of "active CA + optional pending CA".
#[derive(Clone)]
pub(crate) struct LiveCa {
    pub(crate) active: Arc<ActiveCa>,
    pub(crate) pending: Option<Arc<PendingCa>>,
}

impl LiveCa {
    /// PEM bytes the hijack endpoint should serve. Pending wins when present
    /// so callers fetching the cert get the *next* one to trust; once the
    /// rotation commits, the active and pending PEMs are the same.
    pub(crate) fn hijack_cert_pem(&self) -> &Bytes {
        match &self.pending {
            Some(p) => &p.cert_pem,
            None => &self.active.cert_pem,
        }
    }
}

pub(crate) type SharedCaState = Arc<ArcSwap<LiveCa>>;
