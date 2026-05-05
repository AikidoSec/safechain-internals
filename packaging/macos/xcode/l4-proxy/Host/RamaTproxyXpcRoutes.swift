import Foundation
import RamaAppleXpcClient

/// Typed XPC routes exposed by the L4 sysext's router in
/// `proxy-lib-l4-macos/src/xpc_server.rs`. Selectors, field names, and
/// shapes must stay in sync with the Rust `serde` types on each route.

enum AikidoL4GenerateCaCrt: RamaXpcRoute {
    static let selector = "generateCaCrt:withReply:"
    typealias Reply = AikidoL4CaCommandReply
}

enum AikidoL4CommitCaCrt: RamaXpcRoute {
    static let selector = "commitCaCrt:withReply:"
    typealias Reply = AikidoL4CaCommandReply
}

/// Shared reply for `generateCaCrt` / `commitCaCrt` (matches Rust
/// `CaCommandReply`).
///
/// - `generateCaCrt`: `cert_der_b64` carries the freshly-minted (pending)
///   CA certificate so callers can install trust before committing.
/// - `commitCaCrt`: `cert_der_b64` carries the *previous* active CA, so
///   callers can drop its trust. Absent when there was nothing to displace
///   (first-ever commit).
struct AikidoL4CaCommandReply: Decodable {
    let ok: Bool
    let error: String?
    let cert_der_b64: String?
}
