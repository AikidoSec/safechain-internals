use std::sync::Arc;

use arc_swap::ArcSwap;

use super::{
    build_active_from_pending, build_peer_code_signing_requirement, promote_committed_pending,
};
use crate::{
    state::{LiveCa, SharedCaState},
    tls::generate_pending_ca,
};

#[test]
fn promote_committed_pending_preserves_newer_pending_ca() {
    let active_pending = generate_pending_ca().expect("generate initial active ca");
    let committed_pending = Arc::new(generate_pending_ca().expect("generate committed pending ca"));
    let newer_pending = Arc::new(generate_pending_ca().expect("generate newer pending ca"));

    let state: SharedCaState = Arc::new(ArcSwap::from_pointee(LiveCa {
        active: build_active_from_pending(&active_pending),
        pending: Some(committed_pending.clone()),
    }));

    state.rcu(|live| LiveCa {
        active: live.active.clone(),
        pending: Some(newer_pending.clone()),
    });

    let previous_der = promote_committed_pending(
        &state,
        &committed_pending,
        build_active_from_pending(&committed_pending),
    )
    .expect("previous active der should be captured");

    let live = state.load_full();
    assert_eq!(live.active.cert_der, committed_pending.cert_der);
    assert_eq!(previous_der, active_pending.cert_der);
    let still_pending = live
        .pending
        .clone()
        .expect("newer pending ca should be preserved");
    assert!(Arc::ptr_eq(&still_pending, &newer_pending));
}

#[test]
fn build_peer_code_signing_requirement_pins_team_and_identifier() {
    let requirement =
        build_peer_code_signing_requirement("com.aikido.endpoint.proxy.l4.dev", "7VPF8GD6J4")
            .expect("requirement should build");

    assert!(requirement.contains("anchor apple generic"));
    assert!(requirement.contains("identifier \"com.aikido.endpoint.proxy.l4.dev\""));
    assert!(requirement.contains("certificate leaf[subject.OU] = \"7VPF8GD6J4\""));
}
