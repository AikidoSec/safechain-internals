import Darwin
import Foundation
import NetworkExtension
import OSLog
import ObjectiveC
import RamaAppleXpcClient
import Security
import SystemExtensions

private enum HostCommand {
    case start(StartOptions)
    case stop(StopOptions)
    case status
    case generateCaCrt
    case commitCaCrt
    case cleanupLegacyCaCrt
    case deleteCaCrt
    case installExtension
    case allowVpn
    case isExtensionInstalled
    case isExtensionActivated
    case isVpnAllowed
    case help
}

private struct StopOptions {
    var removeProfile = false
    var deactivateExtension = false
}

private struct StartOptions {
    var reportingEndpoint: String?
    var aikidoURL: String?
    var agentToken: String?
    var agentDeviceID: String?
    var resetProfile = false
    var noFirewall = false
}

private struct AgentIdentityPayload: Encodable, Equatable {
    let token: String
    let deviceID: String

    private enum CodingKeys: String, CodingKey {
        case token
        case deviceID = "device_id"
    }
}

/// Engine-config payload forwarded to the sysext through the opaque
/// `providerConfiguration` blob. Wire shape must stay in sync with
/// `ProxyConfig` in `proxy-lib-l4-macos/src/config.rs`.
private struct ProxyEngineConfigPayload: Encodable, Equatable {
    let agentIdentity: AgentIdentityPayload?
    let reportingEndpoint: String?
    let aikidoURL: String?
    let hostBundleID: String
    /// **DEPRECATED — graceful migration only.** PEM forwarded from
    /// the legacy data-protection keychain when an older container
    /// generated the CA before the sysext owned that responsibility.
    /// The sysext uses it for the run only and never persists it.
    let caCertPEM: String?
    /// **DEPRECATED — graceful migration only.** Counterpart to
    /// [`Self.caCertPEM`].
    let caKeyPEM: String?
    let xpcServiceName: String?
    let containerSigningIdentifier: String?
    let containerTeamIdentifier: String?
    let noFirewall: Bool

    private enum CodingKeys: String, CodingKey {
        case agentIdentity = "agent_identity"
        case reportingEndpoint = "reporting_endpoint"
        case aikidoURL = "aikido_url"
        case hostBundleID = "host_bundle_id"
        case caCertPEM = "ca_cert_pem"
        case caKeyPEM = "ca_key_pem"
        case xpcServiceName = "xpc_service_name"
        case containerSigningIdentifier = "container_signing_identifier"
        case containerTeamIdentifier = "container_team_identifier"
        case noFirewall = "no_firewall"
    }
}

private struct LegacyMITMCASecrets: Equatable {
    let certPEM: String
    let keyPEM: String
}

private enum CLIError: LocalizedError {
    case usage(String)
    case invalidArgument(String)
    case runtime(String)

    var errorDescription: String? {
        switch self {
        case .usage(let message), .invalidArgument(let message), .runtime(let message):
            message
        }
    }
}

private enum SystemExtensionActivationOutcome {
    case completed
    case replaced
    case approvalRequired
}

private final class TransparentProxyHostCLI {
    private let managerDescription = "Aikido Endpoint L4 Transparent Proxy"
    private let managerServerAddress = "127.0.0.1"
    private lazy var extensionBundleId = infoString(
        key: "AikidoL4ExtensionBundleIdentifier",
        fallback: "com.aikido.endpoint.proxy.l4.dev.extension"
    )
    /// `NEMachServiceName` exposed by the sysext's `Info.plist`. Forwarded
    /// to the sysext so `XpcListenerConfig::new` and our client agree on
    /// the same string. Intentionally read from the Host's `Info.plist`
    /// (single source of truth) instead of being re-derived from the
    /// bundle identifier — see the rama crate-level docs.
    private lazy var xpcServiceName = infoString(
        key: "AikidoL4ProviderMachServiceName",
        fallback: ""
    )
    private lazy var sharedAccessGroup = infoString(
        key: "AikidoL4SharedAccessGroup",
        fallback: ""
    )
    private lazy var logger = Logger(
        subsystem: "com.aikido.endpoint.proxy.l4", category: "host-main")
    func run(arguments: [String]) -> Int32 {
        do {
            let command = try Self.parse(arguments: arguments)

            switch command {
            case .start(let options):
                try start(options: options)
                return EXIT_SUCCESS
            case .stop(let options):
                try stop(options: options)
                return EXIT_SUCCESS
            case .status:
                try status()
                return EXIT_SUCCESS
            case .generateCaCrt:
                try generateCaCrt()
                return EXIT_SUCCESS
            case .commitCaCrt:
                try commitCaCrt()
                return EXIT_SUCCESS
            case .cleanupLegacyCaCrt:
                cleanupLegacyCaCrt()
                return EXIT_SUCCESS
            case .deleteCaCrt:
                deleteCaCrt()
                return EXIT_SUCCESS
            case .installExtension:
                try installExtension()
                return EXIT_SUCCESS
            case .allowVpn:
                try allowVpn()
                return EXIT_SUCCESS
            case .isExtensionInstalled:
                try checkExtensionInstalled()
                return EXIT_SUCCESS
            case .isExtensionActivated:
                try checkExtensionActivated()
                return EXIT_SUCCESS
            case .isVpnAllowed:
                try checkVpnAllowed()
                return EXIT_SUCCESS
            case .help:
                print(Self.usage())
                return EXIT_SUCCESS
            }
        } catch let error as CLIError {
            Self.writeStderr("error: \(error.localizedDescription)\n")
            if case .usage = error {
                Self.writeStderr("\n\(Self.usage())\n")
            }
            return EXIT_FAILURE
        } catch {
            Self.writeStderr("error: \(error.localizedDescription)\n")
            return EXIT_FAILURE
        }
    }

    private func start(options: StartOptions) throws {
        let activationOutcome = try ensureSystemExtensionActivated()
        guard activationOutcome != .approvalRequired else {
            throw CLIError.runtime(
                "system extension approval required; open System Settings > General > Login Items & Extensions > Network Extensions"
            )
        }

        let legacyCA = loadLegacyMITMCAOrNil()
        if legacyCA != nil {
            log(
                "DEPRECATED: forwarding legacy MITM CA from data-protection keychain to sysext via opaque config. The sysext will use it for this run only and will NOT persist it. Rotate via `generate-ca-crt` + `commit-ca-crt` to retire the legacy CA."
            )
        }

        let engineConfigJSON = try Self.makeEngineConfigJSON(
            from: options,
            legacyCA: legacyCA,
            xpcServiceName: xpcServiceName.nilIfEmpty,
            containerTeamIdentifier: containerTeamIdentifier()
        )
        let existingManagers = try loadManagers()

        if options.resetProfile {
            let managersToRemove = matchingManagers(from: existingManagers)
            if !managersToRemove.isEmpty {
                log("removing \(managersToRemove.count) saved transparent proxy manager(s)")
                try removeManagersFromPreferences(managersToRemove)
            }
        }

        let manager = try prepareManager(
            existingManagers: options.resetProfile ? [] : existingManagers,
            engineConfigJSON: engineConfigJSON)

        let mustRestartBecauseBinaryChanged = activationOutcome == .replaced

        if mustRestartBecauseBinaryChanged
            || shouldRestartTunnel(manager: manager, expectedEngineConfigJSON: engineConfigJSON)
        {
            log(
                "configuration or extension binary changed while proxy was active; restarting tunnel"
            )
            manager.connection.stopVPNTunnel()
            waitUntilDisconnected(manager: manager, attempts: 40)
        } else if isActive(manager.connection.status) {
            print("status: \(statusString(manager.connection.status))")
            return
        }

        do {
            try manager.connection.startVPNTunnel()
            log("transparent proxy start requested")
        } catch {
            throw CLIError.runtime(
                "failed to start transparent proxy: \(error.localizedDescription)")
        }

        let status = waitForSteadyState(manager: manager, attempts: 20)
        print("status: \(statusString(status))")
    }

    private func stop(options: StopOptions) throws {
        let managers = try loadManagers()
        let manager = selectManager(from: managers)

        if let manager,
            manager.connection.status != .disconnected && manager.connection.status != .invalid
        {
            log("stopping transparent proxy tunnel")
            manager.connection.stopVPNTunnel()
            waitUntilDisconnected(manager: manager, attempts: 40)
        }

        if options.removeProfile {
            let managersToRemove = matchingManagers(from: managers)
            if !managersToRemove.isEmpty {
                log("removing \(managersToRemove.count) saved transparent proxy manager(s)")
                try removeManagersFromPreferences(managersToRemove)
            }
        }

        if options.deactivateExtension {
            try deactivateSystemExtension()
        }

        if let manager {
            print(
                "status: \(options.removeProfile ? "removed" : statusString(manager.connection.status))"
            )
        } else {
            print("status: not-installed")
        }
    }

    private func status() throws {
        guard let manager = selectManager(from: try loadManagers()) else {
            print("status: not-installed")
            return
        }

        print("status: \(statusString(manager.connection.status))")
    }

    // MARK: - CA commands

    private func generateCaCrt() throws {
        let serviceName = try requireXpcServiceName()
        log("generate-ca-crt: invoking XPC route on \(serviceName)")
        let reply = try runXpc { client in
            try await client.call(AikidoL4GenerateCaCrt.self)
        }
        if !reply.ok {
            throw CLIError.runtime(
                "generate-ca-crt failed in sysext: \(reply.error ?? "unknown error)")")
        }
        guard let der = reply.cert_der_b64 else {
            throw CLIError.runtime(
                "generate-ca-crt sysext reply missing `cert_der_b64`; refusing to claim success"
            )
        }
        // Single line: `cert_der_b64: <base64>`. Stable for callers parsing
        // stdout (e.g. the Go daemon).
        print("cert_der_b64: \(der)")
    }

    private func commitCaCrt() throws {
        let serviceName = try requireXpcServiceName()
        log("commit-ca-crt: invoking XPC route on \(serviceName)")
        let reply = try runXpc { client in
            try await client.call(AikidoL4CommitCaCrt.self)
        }
        if !reply.ok {
            throw CLIError.runtime(
                "commit-ca-crt failed in sysext: \(reply.error ?? "unknown error)")")
        }
        // sysext successfully swapped the active CA. Now retire the legacy
        // data-protection-keychain entries (idempotent; no-op when absent).
        // This is the only point at which legacy state is removed: until
        // commit lands, callers may need it for rollback.
        let legacyOutcome = deleteLegacyDataProtectionEntries()

        if let der = reply.cert_der_b64 {
            print("previous_cert_der_b64: \(der)")
        } else {
            print("previous_cert_der_b64:")
        }

        // The new CA is already active in the sysext. If we could not retire
        // the legacy plaintext key material, surface that to the caller via a
        // non-zero exit so it doesn't get logged-and-forgotten — leaving the
        // old private key sitting in the data-protection keychain is a real
        // (if narrow) audit finding. The caller still has the previous DER
        // it needs from stdout above, and can re-run commit-ca-crt to retry
        // the cleanup; both keychain ops are idempotent.
        if case .partial(let messages) = legacyOutcome {
            // The sysext swap succeeded and the new CA is live, but the
            // legacy plaintext key material is still sitting in the
            // data-protection keychain. The sysext now prefers SE-backed CAs
            // over legacy, so this is not a runtime regression — but the
            // caller MUST know about it (audit / hygiene). Run
            // `cleanup-legacy-ca-crt` to retry; both keychain ops are
            // idempotent.
            throw CLIError.runtime(
                "commit-ca-crt: rotation committed in sysext, but legacy data-protection keychain cleanup failed (\(messages.joined(separator: "; "))). Run `cleanup-legacy-ca-crt` to retry."
            )
        }
    }

    private func cleanupLegacyCaCrt() {
        let outcome = deleteLegacyDataProtectionEntries()
        switch outcome {
        case .ok:
            print("legacy-ca-crt: cleaned")
        case .partial(let messages):
            print("legacy-ca-crt: cleaned (with warnings)")
            for message in messages {
                Self.writeStderr("warn: \(message)\n")
            }
        }
    }

    private func deleteCaCrt() {
        // No XPC: we are nuking every keychain artefact that may carry
        // MITM CA material on this machine. The sysext's in-memory copy
        // of the CA survives until the next sysext restart — that is
        // expected: callers pair `delete-ca-crt` with a tunnel
        // stop/restart when a hard reset is intended.
        deleteLegacyDataProtectionEntries()
        let systemKeychainResult = deleteSystemKeychainCAEntries()
        switch systemKeychainResult {
        case .ok:
            print("ca-crt: deleted")
        case .partial(let messages):
            print("ca-crt: deleted (with warnings)")
            for message in messages {
                Self.writeStderr("warn: \(message)\n")
            }
        }
    }

    private func installExtension() throws {
        let outcome = try ensureSystemExtensionActivated()
        switch outcome {
        case .completed:
            print("extension: activated")
        case .replaced:
            print("extension: replaced")
        case .approvalRequired:
            print("extension: approval-required")
        }
    }

    private func allowVpn() throws {
        let existingManagers = try loadManagers()
        do {
            let _ = try prepareManager(existingManagers: existingManagers, engineConfigJSON: nil)
        } catch {
            let ns = error as NSError
            if ns.domain == NEVPNErrorDomain
                && ns.code == NEVPNError.configurationReadWriteFailed.rawValue
            {
                print("vpn: not-allowed")
                return
            }
            throw error
        }
        print("vpn: allowed")
    }

    private func listExtensionLines() throws -> [Substring] {
        let output: String
        do {
            output = try runProcessCaptureStdout(
                launchPath: "/usr/bin/systemextensionsctl",
                arguments: ["list"]
            )
        } catch {
            log("failed to list system extensions: \(error.localizedDescription)")
            return []
        }
        return output.split(separator: "\n").filter {
            $0.contains(extensionBundleId) && !$0.contains("terminated")
        }
    }

    private func checkExtensionInstalled() throws {
        let lines = try listExtensionLines()
        let installed = !lines.isEmpty
        print("extension-installed: \(installed)")
    }

    private func checkExtensionActivated() throws {
        let lines = try listExtensionLines()
        let activated = lines.contains { $0.contains("[activated enabled]") }
        print("extension-activated: \(activated)")
    }

    private func checkVpnAllowed() throws {
        let managers = try loadManagers()
        let allowed = selectManager(from: managers) != nil
        print("vpn-allowed: \(allowed)")
    }

    // MARK: - NE machinery

    private func loadManagers() throws -> [NETransparentProxyManager] {
        try waitForResult("load transparent proxy managers") { completion in
            NETransparentProxyManager.loadAllFromPreferences { managers, error in
                if let error {
                    completion(.failure(error))
                    return
                }
                completion(.success(managers ?? []))
            }
        }
    }

    private func ensureSystemExtensionActivated() throws -> SystemExtensionActivationOutcome {
        log("submitting system extension activation request for \(extensionBundleId)")

        return try waitForResult("activate system extension", timeout: 30) { completion in
            let delegate = SystemExtensionRequestDelegate(
                extensionBundleId: extensionBundleId,
                onFinish: { outcome in completion(.success(outcome)) },
                onApprovalRequired: { completion(.success(.approvalRequired)) },
                onFailure: { completion(.failure($0)) },
                log: { [weak self] message in self?.log(message) },
                logError: { [weak self] prefix, error in self?.logError(prefix, error) }
            )

            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: extensionBundleId,
                queue: .main
            )
            request.delegate = delegate
            objc_setAssociatedObject(
                request,
                &AssociatedKeys.systemExtensionDelegate,
                delegate,
                .OBJC_ASSOCIATION_RETAIN_NONATOMIC
            )
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func deactivateSystemExtension() throws {
        log("submitting system extension deactivation request for \(extensionBundleId)")

        let _: SystemExtensionActivationOutcome = try waitForResult(
            "deactivate system extension", timeout: 30
        ) { completion in
            let delegate = SystemExtensionRequestDelegate(
                extensionBundleId: extensionBundleId,
                onFinish: { outcome in completion(.success(outcome)) },
                onApprovalRequired: { completion(.success(.approvalRequired)) },
                onFailure: { completion(.failure($0)) },
                log: { [weak self] message in self?.log(message) },
                logError: { [weak self] prefix, error in self?.logError(prefix, error) }
            )

            let request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: extensionBundleId,
                queue: .main
            )
            request.delegate = delegate
            objc_setAssociatedObject(
                request,
                &AssociatedKeys.systemExtensionDelegate,
                delegate,
                .OBJC_ASSOCIATION_RETAIN_NONATOMIC
            )
            OSSystemExtensionManager.shared.submitRequest(request)
        }

        log("system extension deactivated")
    }

    private func prepareManager(
        existingManagers: [NETransparentProxyManager],
        engineConfigJSON: String?
    ) throws -> NETransparentProxyManager {
        let existingManager = selectManager(from: existingManagers)
        let manager = existingManager ?? NETransparentProxyManager()
        let changed = configure(manager: manager, engineConfigJSON: engineConfigJSON)

        if changed || existingManager == nil {
            log(
                existingManager == nil ? "saving new proxy manager" : "saving updated proxy manager"
            )
            return try save(manager: manager)
        }

        return manager
    }

    private func save(manager: NETransparentProxyManager) throws -> NETransparentProxyManager {
        try waitForResult("save transparent proxy manager") { completion in
            manager.saveToPreferences { saveError in
                if let saveError {
                    completion(.failure(saveError))
                    return
                }

                manager.loadFromPreferences { loadError in
                    if let loadError {
                        completion(.failure(loadError))
                        return
                    }
                    completion(.success(manager))
                }
            }
        }
    }

    private func removeManagersFromPreferences(_ managers: [NETransparentProxyManager]) throws {
        for manager in managers {
            try waitForResult("remove transparent proxy manager") {
                (completion: @escaping (Result<Void, Error>) -> Void) in
                manager.removeFromPreferences { error in
                    if let error {
                        completion(.failure(error))
                        return
                    }
                    completion(.success(()))
                }
            }
        }
    }

    private func configure(manager: NETransparentProxyManager, engineConfigJSON: String?) -> Bool {
        var changed = false

        let proto =
            (manager.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()

        if proto.providerBundleIdentifier != extensionBundleId {
            proto.providerBundleIdentifier = extensionBundleId
            changed = true
        }

        if proto.serverAddress != managerServerAddress {
            proto.serverAddress = managerServerAddress
            changed = true
        }

        if proto.disconnectOnSleep {
            // ensure the tunnel remains active across system sleep/wake cycles
            proto.disconnectOnSleep = false
            changed = true
        }

        let expectedConfiguration = providerConfiguration(engineConfigJSON: engineConfigJSON)
        let currentConfig = proto.providerConfiguration as? [String: String]
        if currentConfig != expectedConfiguration {
            proto.providerConfiguration = expectedConfiguration
            changed = true
        }

        if manager.localizedDescription != managerDescription {
            manager.localizedDescription = managerDescription
            changed = true
        }

        if manager.protocolConfiguration == nil
            || !protocolMatchesExpected(proto, engineConfigJSON: engineConfigJSON)
        {
            manager.protocolConfiguration = proto
            changed = true
        }

        if !manager.isEnabled {
            manager.isEnabled = true
            changed = true
        }

        return changed
    }

    private func protocolMatchesExpected(
        _ proto: NETunnelProviderProtocol,
        engineConfigJSON: String?
    ) -> Bool {
        proto.providerBundleIdentifier == extensionBundleId
            && proto.serverAddress == managerServerAddress
            && (proto.providerConfiguration as? [String: String])
                == providerConfiguration(engineConfigJSON: engineConfigJSON)
    }

    private func providerConfiguration(engineConfigJSON: String?) -> [String: String]? {
        guard let engineConfigJSON else {
            return nil
        }
        return ["engineConfigJson": engineConfigJSON]
    }

    private func selectManager(from managers: [NETransparentProxyManager])
        -> NETransparentProxyManager?
    {
        if let exact = managers.first(where: { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == extensionBundleId
        }) {
            return exact
        }

        return managers.first(where: { $0.localizedDescription == managerDescription })
    }

    private func matchingManagers(from managers: [NETransparentProxyManager])
        -> [NETransparentProxyManager]
    {
        managers.filter { manager in
            if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                proto.providerBundleIdentifier == extensionBundleId
            {
                return true
            }

            return manager.localizedDescription == managerDescription
        }
    }

    private func shouldRestartTunnel(
        manager: NETransparentProxyManager,
        expectedEngineConfigJSON: String?
    ) -> Bool {
        guard isActive(manager.connection.status) else {
            return false
        }

        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            return false
        }

        return (proto.providerConfiguration as? [String: String])
            != providerConfiguration(engineConfigJSON: expectedEngineConfigJSON)
    }

    @discardableResult
    private func waitUntilDisconnected(manager: NETransparentProxyManager, attempts: Int)
        -> NEVPNStatus
    {
        var remainingAttempts = attempts
        while remainingAttempts > 0 {
            let status = manager.connection.status
            if status == .disconnected || status == .invalid {
                return status
            }

            remainingAttempts -= 1
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.25))
        }

        return manager.connection.status
    }

    private func waitForSteadyState(manager: NETransparentProxyManager, attempts: Int)
        -> NEVPNStatus
    {
        var remainingAttempts = attempts
        while remainingAttempts > 0 {
            let status = manager.connection.status
            if status != .connecting && status != .disconnecting {
                return status
            }

            remainingAttempts -= 1
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.25))
        }

        return manager.connection.status
    }

    private func isActive(_ status: NEVPNStatus) -> Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    private func statusString(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }

    private func waitForResult<T>(
        _ operation: String,
        timeout: TimeInterval = 15,
        body: (@escaping (Result<T, Error>) -> Void) -> Void
    ) throws -> T {
        var result: Result<T, Error>?

        body { callbackResult in
            result = callbackResult
        }

        let deadline = Date(timeIntervalSinceNow: timeout)
        while result == nil && Date() < deadline {
            RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.05))
        }

        guard let result else {
            throw CLIError.runtime("timed out while trying to \(operation)")
        }

        switch result {
        case .success(let value):
            return value
        case .failure(let error):
            logError("\(operation) failed", error)
            throw CLIError.runtime("\(operation) failed: \(error.localizedDescription)")
        }
    }

    // MARK: - XPC plumbing

    private func requireXpcServiceName() throws -> String {
        let name = xpcServiceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            throw CLIError.runtime(
                "AikidoL4ProviderMachServiceName missing from Info.plist; the host CLI cannot reach the sysext over XPC. Rebuild the Host bundle with the patched Info.plist."
            )
        }
        return name
    }

    private func containerTeamIdentifier() -> String? {
        let group = sharedAccessGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !group.isEmpty else {
            return nil
        }
        guard let prefix = group.split(separator: ".", maxSplits: 1).first else {
            return nil
        }
        let teamID = String(prefix)
        return teamID.isEmpty ? nil : teamID
    }

    private func runXpc<T>(_ body: @escaping (RamaXpcClient) async throws -> T) throws -> T {
        let serviceName = try requireXpcServiceName()
        let client = RamaXpcClient(serviceName: serviceName)

        var result: Result<T, Error>?
        let semaphore = DispatchSemaphore(value: 0)

        Task.detached {
            do {
                let value = try await body(client)
                result = .success(value)
            } catch {
                result = .failure(error)
            }
            semaphore.signal()
        }

        // 30s is plenty for one-shot generate / commit calls. Persist of a
        // freshly-minted CA does an SE encrypt + 3 keychain writes — sub-second
        // in practice. Tunable here if it ever changes.
        let deadline = DispatchTime.now() + .seconds(30)
        if semaphore.wait(timeout: deadline) == .timedOut {
            throw CLIError.runtime(
                "timed out waiting for XPC reply from sysext (service: \(serviceName))"
            )
        }

        switch result {
        case .success(let value):
            return value
        case .failure(let err):
            throw CLIError.runtime(
                "XPC call to sysext failed (service: \(serviceName)): \(err.localizedDescription)"
            )
        case .none:
            throw CLIError.runtime(
                "XPC call to sysext returned no result (service: \(serviceName))"
            )
        }
    }

    // MARK: - Legacy data-protection keychain (graceful migration)

    /// **DEPRECATED — graceful migration only.** Older container builds
    /// stored the CA inside the user's data-protection keychain under
    /// these constants. We keep the ability to *load* such material so it
    /// can be passed to the sysext while a customer migrates; we never
    /// store anything there ourselves anymore. Once the graceful period
    /// ends the entire branch (constants + helpers) can be removed.
    private static let legacySecretAccount = "safechain-lib-l4-proxy-macos"
    private static let legacySecretServiceKeyPEM = "tls-root-selfsigned-ca-key"
    private static let legacySecretServiceCertPEM = "tls-root-selfsigned-ca-crt"
    private static let legacySecretServices = [
        legacySecretServiceKeyPEM,
        legacySecretServiceCertPEM,
    ]

    private func loadLegacyMITMCAOrNil() -> LegacyMITMCASecrets? {
        let key = try? loadLegacySecret(service: Self.legacySecretServiceKeyPEM)
        let cert = try? loadLegacySecret(service: Self.legacySecretServiceCertPEM)
        guard let key = key ?? nil, let cert = cert ?? nil else {
            return nil
        }
        return LegacyMITMCASecrets(certPEM: cert, keyPEM: key)
    }

    private func loadLegacySecret(service: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.legacySecretAccount,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw CLIError.runtime("legacy keychain item for \(service) did not return Data")
            }
            guard let value = String(data: data, encoding: .utf8) else {
                throw CLIError.runtime("legacy keychain item for \(service) was not valid UTF-8")
            }
            return value
        case errSecItemNotFound:
            return nil
        default:
            throw CLIError.runtime(
                "failed to load legacy keychain secret \(service): OSStatus \(status)")
        }
    }

    @discardableResult
    private func deleteLegacyDataProtectionEntries() -> DeleteOutcome {
        var warnings: [String] = []
        for service in Self.legacySecretServices {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: Self.legacySecretAccount,
                kSecUseDataProtectionKeychain as String: true,
            ]
            let status = SecItemDelete(query as CFDictionary)
            switch status {
            case errSecSuccess:
                log("deleted legacy data-protection keychain entry: \(service)")
            case errSecItemNotFound:
                continue
            default:
                let msg =
                    "failed to delete legacy data-protection keychain entry \(service): OSStatus \(status)"
                log(msg)
                warnings.append(msg)
            }
        }
        return warnings.isEmpty ? .ok : .partial(warnings)
    }

    // MARK: - System Keychain (SE-encrypted CA storage)

    /// Service / account constants must match the sysext side
    /// (`proxy-lib-l4-macos/src/tls.rs`). Keep in sync.
    private static let systemCAAccount = "com.aikido.endpoint.proxy.l4"
    private static let systemCAServiceCert = "aikido-l4-mitm-ca-crt"
    private static let systemCAServiceKey = "aikido-l4-mitm-ca-key"
    private static let systemCAServiceSEKey = "aikido-l4-mitm-ca-se-key"
    private static let systemCAAllServices = [
        systemCAServiceSEKey,
        systemCAServiceCert,
        systemCAServiceKey,
    ]

    private enum DeleteOutcome {
        case ok
        case partial([String])
    }

    private func deleteSystemKeychainCAEntries() -> DeleteOutcome {
        // We must hit the file-based System Keychain
        // (`/Library/Keychains/System.keychain`), which is what the sysext
        // writes to via `SecKeychainAddGenericPassword`. The modern
        // `SecItem*` APIs default to the user's keychains and ignore that
        // file even with `kSecUseDataProtectionKeychain: false`, so we have
        // to drive the same legacy `SecKeychain*` family rama uses on the
        // sysext side. Writing/deleting there requires root privileges (or
        // an admin auth prompt); the Aikido CLI runs as root in the
        // daemon-driven flow.
        var keychain: SecKeychain?
        let openStatus = "/Library/Keychains/System.keychain".withCString { path in
            SecKeychainOpen(path, &keychain)
        }
        guard openStatus == errSecSuccess, let keychain else {
            return .partial([
                "failed to open /Library/Keychains/System.keychain: OSStatus \(openStatus)"
            ])
        }

        var warnings: [String] = []
        for service in Self.systemCAAllServices {
            let serviceBytes = Array(service.utf8)
            let accountBytes = Array(Self.systemCAAccount.utf8)
            var item: SecKeychainItem?

            let findStatus = serviceBytes.withUnsafeBufferPointer { svc in
                accountBytes.withUnsafeBufferPointer { acc in
                    SecKeychainFindGenericPassword(
                        keychain,
                        UInt32(svc.count),
                        svc.baseAddress,
                        UInt32(acc.count),
                        acc.baseAddress,
                        nil,
                        nil,
                        &item
                    )
                }
            }

            switch findStatus {
            case errSecSuccess:
                guard let item else {
                    continue
                }
                let deleteStatus = SecKeychainItemDelete(item)
                if deleteStatus == errSecSuccess {
                    log("deleted System Keychain entry: \(service)")
                } else {
                    let msg =
                        "failed to delete System Keychain entry \(service): OSStatus \(deleteStatus)"
                    log(msg)
                    warnings.append(msg)
                }
            case errSecItemNotFound:
                continue
            default:
                let msg =
                    "failed to look up System Keychain entry \(service): OSStatus \(findStatus)"
                log(msg)
                warnings.append(msg)
            }
        }
        return warnings.isEmpty ? .ok : .partial(warnings)
    }

    // MARK: - Logging

    private func log(_ message: String) {
        logger.info("\(message, privacy: .public)")
    }

    private func logError(_ prefix: String, _ error: Error) {
        let ns = error as NSError
        logger.error(
            "\(prefix, privacy: .public): domain=\(ns.domain, privacy: .public) code=\(ns.code, privacy: .public) description=\(ns.localizedDescription, privacy: .public)"
        )
    }

    private func infoString(key: String, fallback: String) -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String else {
            return fallback
        }

        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? fallback : trimmed
    }

    private static func parse(arguments: [String]) throws -> HostCommand {
        guard let first = arguments.first else {
            return .help
        }

        if first == "--help" || first == "-h" || first == "help" {
            return .help
        }

        switch first {
        case "start":
            let startArguments = Array(arguments.dropFirst())
            if startArguments.contains("--help") || startArguments.contains("-h") {
                return .help
            }
            return .start(try parseStartOptions(arguments: startArguments))
        case "stop":
            let stopArguments = Array(arguments.dropFirst())
            return .stop(try parseStopOptions(arguments: stopArguments))
        case "status":
            try assertNoExtraArgs(arguments, command: "status")
            return .status
        case "generate-ca-crt":
            try assertNoExtraArgs(arguments, command: "generate-ca-crt")
            return .generateCaCrt
        case "commit-ca-crt":
            try assertNoExtraArgs(arguments, command: "commit-ca-crt")
            return .commitCaCrt
        case "cleanup-legacy-ca-crt":
            try assertNoExtraArgs(arguments, command: "cleanup-legacy-ca-crt")
            return .cleanupLegacyCaCrt
        case "delete-ca-crt":
            try assertNoExtraArgs(arguments, command: "delete-ca-crt")
            return .deleteCaCrt
        case "install-extension":
            try assertNoExtraArgs(arguments, command: "install-extension")
            return .installExtension
        case "allow-vpn":
            try assertNoExtraArgs(arguments, command: "allow-vpn")
            return .allowVpn
        case "is-extension-installed":
            try assertNoExtraArgs(arguments, command: "is-extension-installed")
            return .isExtensionInstalled
        case "is-extension-activated":
            try assertNoExtraArgs(arguments, command: "is-extension-activated")
            return .isExtensionActivated
        case "is-vpn-allowed":
            try assertNoExtraArgs(arguments, command: "is-vpn-allowed")
            return .isVpnAllowed
        default:
            throw CLIError.usage("unknown command: \(first)")
        }
    }

    private static func assertNoExtraArgs(_ arguments: [String], command: String) throws {
        guard arguments.count == 1 else {
            throw CLIError.usage("`\(command)` does not accept additional arguments")
        }
    }

    private static func parseStartOptions(arguments: [String]) throws -> StartOptions {
        var options = StartOptions()
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--reporting-endpoint":
                options.reportingEndpoint = try consumeValue(
                    flag: argument, arguments: arguments, index: &index)
                try validateAbsoluteURL(options.reportingEndpoint, flag: argument)
            case "--aikido-url":
                options.aikidoURL = try consumeValue(
                    flag: argument, arguments: arguments, index: &index)
                try validateAbsoluteURL(options.aikidoURL, flag: argument)
            case "--agent-token":
                options.agentToken = try consumeValue(
                    flag: argument, arguments: arguments, index: &index)
            case "--agent-device-id":
                options.agentDeviceID = try consumeValue(
                    flag: argument, arguments: arguments, index: &index)
            case "--reset-profile":
                options.resetProfile = true
            case "--no-firewall":
                options.noFirewall = true
            default:
                throw CLIError.usage("unknown `start` argument: \(argument)")
            }

            index += 1
        }

        let hasAgentToken = options.agentToken != nil
        let hasAgentDeviceID = options.agentDeviceID != nil
        if hasAgentToken != hasAgentDeviceID {
            throw CLIError.invalidArgument(
                "`--agent-token` and `--agent-device-id` must be provided together"
            )
        }

        return options
    }

    private static func parseStopOptions(arguments: [String]) throws -> StopOptions {
        var options = StopOptions()
        for argument in arguments {
            switch argument {
            case "--remove-profile":
                options.removeProfile = true
            case "--deactivate-extension":
                options.deactivateExtension = true
            default:
                throw CLIError.usage("unknown `stop` argument: \(argument)")
            }
        }
        return options
    }

    private static func consumeValue(
        flag: String,
        arguments: [String],
        index: inout Int
    ) throws -> String {
        let valueIndex = index + 1
        guard valueIndex < arguments.count else {
            throw CLIError.invalidArgument("missing value for \(flag)")
        }

        let value = arguments[valueIndex].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            throw CLIError.invalidArgument("empty value for \(flag) is not allowed")
        }

        index = valueIndex
        return value
    }

    private static func validateAbsoluteURL(_ rawValue: String?, flag: String) throws {
        guard let rawValue else {
            return
        }

        guard let components = URLComponents(string: rawValue),
            let scheme = components.scheme,
            !scheme.isEmpty,
            components.host != nil
        else {
            throw CLIError.invalidArgument("\(flag) must be an absolute URL")
        }
    }

    private static func makeEngineConfigJSON(
        from options: StartOptions,
        legacyCA: LegacyMITMCASecrets?,
        xpcServiceName: String?,
        containerTeamIdentifier: String?
    ) throws -> String? {
        let agentIdentity: AgentIdentityPayload?
        if let token = options.agentToken, let deviceID = options.agentDeviceID {
            agentIdentity = AgentIdentityPayload(token: token, deviceID: deviceID)
        } else {
            agentIdentity = nil
        }

        let containerSigningIdentifier = Bundle.main.bundleIdentifier ?? "com.aikido.endpoint.proxy.l4.dev"

        let payload = ProxyEngineConfigPayload(
            agentIdentity: agentIdentity,
            reportingEndpoint: options.reportingEndpoint,
            aikidoURL: options.aikidoURL,
            hostBundleID: containerSigningIdentifier,
            caCertPEM: legacyCA?.certPEM,
            caKeyPEM: legacyCA?.keyPEM,
            xpcServiceName: xpcServiceName,
            containerSigningIdentifier: containerSigningIdentifier,
            containerTeamIdentifier: containerTeamIdentifier,
            noFirewall: options.noFirewall
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(payload)
        guard let json = String(data: data, encoding: .utf8) else {
            throw CLIError.runtime("failed to encode transparent proxy config as UTF-8 JSON")
        }
        return json
    }

    private func runProcessCaptureStdout(
        launchPath: String,
        arguments: [String],
        stdin: String? = nil
    ) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let stdinPipe: Pipe?
        if stdin != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            stdinPipe = pipe
        } else {
            stdinPipe = nil
        }

        do {
            try process.run()
        } catch {
            throw CLIError.runtime("failed to launch \(launchPath): \(error.localizedDescription)")
        }

        if let stdin, let stdinPipe, let data = stdin.data(using: .utf8) {
            stdinPipe.fileHandleForWriting.write(data)
            try? stdinPipe.fileHandleForWriting.close()
        }

        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        let stdoutText = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderrText = String(data: stderrData, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            throw CLIError.runtime(
                "command failed: \(launchPath) \(arguments.joined(separator: " ")): \(stderrText.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }

        guard !stdoutText.isEmpty else {
            throw CLIError.runtime(
                "command produced no stdout: \(launchPath) \(arguments.joined(separator: " "))"
            )
        }

        return stdoutText
    }

    private static func usage() -> String {
        """
        Usage:
          "Aikido Network Extension" start [options]
          "Aikido Network Extension" stop [options]
          "Aikido Network Extension" status
          "Aikido Network Extension" generate-ca-crt
          "Aikido Network Extension" commit-ca-crt
          "Aikido Network Extension" cleanup-legacy-ca-crt
          "Aikido Network Extension" delete-ca-crt
          "Aikido Network Extension" install-extension
          "Aikido Network Extension" allow-vpn
          "Aikido Network Extension" is-extension-installed
          "Aikido Network Extension" is-extension-activated
          "Aikido Network Extension" is-vpn-allowed

        Commands:
          start                  Install or update the transparent proxy profile and request that it starts.
          stop                   Request that the transparent proxy tunnel stops.
          status                 Show the current Network Extension status.
          generate-ca-crt        Ask the sysext to mint a fresh MITM CA in memory and park it
                                 as the pending one. The active TLS interception keeps using
                                 the previous CA, but the hijack endpoint serves the pending
                                 PEM so callers can install trust before commit. Prints the
                                 new cert DER (base64) on stdout as `cert_der_b64: <b64>`.
          commit-ca-crt          Persist the pending CA in the SE-encrypted system keychain
                                 and atomically swap it in as the active CA. Fails when no
                                 pending CA is parked. On success, also wipes any legacy CA
                                 entries in the data-protection keychain. Prints the previous
                                 active cert DER (base64) on stdout as
                                 `previous_cert_der_b64: <b64>` (empty when nothing was displaced).
                                 Exits non-zero if the rotation succeeded but the legacy
                                 cleanup step failed; run `cleanup-legacy-ca-crt` to retry.
          cleanup-legacy-ca-crt  Idempotent. Wipes the legacy data-protection keychain entries
                                 left over from pre-sysext-owned-CA installs. Safe to run any
                                 time; does not touch the SE-encrypted active CA.
          delete-ca-crt          Wipe every MITM CA artefact from the keychains: SE-wrapped
                                 key blob, encrypted cert, encrypted key (system keychain),
                                 and the legacy data-protection entries. Idempotent. Note: the
                                 sysext keeps its in-memory CA copy until restart.
          install-extension      Install the system extension (triggers Network Extension approval).
          allow-vpn              Save the VPN profile (triggers Allow VPN Configuration approval).
          is-extension-installed Check if the system extension appears in the extensions list (no prompts).
          is-extension-activated Check if the system extension is activated and enabled (no prompts).
          is-vpn-allowed         Check if a VPN profile has been saved (no prompts).

        Stop options:
          --remove-profile             Remove the saved Network Extension profile after stopping.
          --deactivate-extension       Deactivate the system extension (for uninstall).

        Start options:
          --reporting-endpoint URL   POST blocked-event reports to this absolute URL.
          --aikido-url URL           Override the Aikido app base URL used by the extension.
          --agent-token TOKEN        Agent token to forward to the extension config.
          --agent-device-id ID       Agent device identifier to forward to the extension config.
          --reset-profile            Remove the saved Network Extension profile before starting.
          --no-firewall              Don't setup the firewall.
          --help                     Show this help text.

        Notes:
          - The transparent proxy extension is managed by macOS after `start`; this host process
            does not need to stay alive for the proxy to keep running.
          - Provide both `--agent-token` and `--agent-device-id` together or omit both.
          - `generate-ca-crt` / `commit-ca-crt` reach the sysext over XPC. The Mach service name
            comes from the Host bundle's `AikidoL4ProviderMachServiceName` Info.plist key.
        """
    }

    private static func writeStderr(_ text: String) {
        guard let data = text.data(using: .utf8) else {
            return
        }
        FileHandle.standardError.write(data)
    }
}

private enum AssociatedKeys {
    static var systemExtensionDelegate: UInt8 = 0
}

extension String {
    fileprivate var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

private final class SystemExtensionRequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private let extensionBundleId: String
    private let onFinish: (SystemExtensionActivationOutcome) -> Void
    private let onApprovalRequired: () -> Void
    private let onFailure: (Error) -> Void
    private let log: (String) -> Void
    private let logError: (String, Error) -> Void

    private var didReplace = false

    init(
        extensionBundleId: String,
        onFinish: @escaping (SystemExtensionActivationOutcome) -> Void,
        onApprovalRequired: @escaping () -> Void,
        onFailure: @escaping (Error) -> Void,
        log: @escaping (String) -> Void,
        logError: @escaping (String, Error) -> Void
    ) {
        self.extensionBundleId = extensionBundleId
        self.onFinish = onFinish
        self.onApprovalRequired = onApprovalRequired
        self.onFailure = onFailure
        self.log = log
        self.logError = logError
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log(
            "system extension approval required for \(extensionBundleId); open System Settings > General > Login Items & Extensions > Network Extensions"
        )
        onApprovalRequired()
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        log(
            "system extension activation finished for \(extensionBundleId), result: \(result.rawValue), replaced: \(didReplace)"
        )
        onFinish(didReplace ? .replaced : .completed)
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        logError("system extension activation failed for \(extensionBundleId)", error)
        onFailure(error)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        didReplace = true
        log(
            "replacing system extension short \(existing.bundleShortVersion) build \(existing.bundleVersion) with short \(ext.bundleShortVersion) build \(ext.bundleVersion)"
        )
        return .replace
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
let exitCode = TransparentProxyHostCLI().run(arguments: arguments)
exit(exitCode)
