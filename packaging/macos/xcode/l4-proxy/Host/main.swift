import Darwin
import Foundation
import NetworkExtension
import OSLog
import ObjectiveC
import Security
import SystemExtensions

private enum HostCommand {
    case start(StartOptions)
    case stop(StopOptions)
    case status
    case cleanSecrets
    case help
}

private struct StopOptions {
    var removeProfile = false
    var cleanSecrets = false
}

private struct StartOptions {
    var reportingEndpoint: String?
    var aikidoURL: String?
    var agentToken: String?
    var agentDeviceID: String?
    var resetProfile = false
}

private struct AgentIdentityPayload: Encodable, Equatable {
    let token: String
    let deviceID: String

    private enum CodingKeys: String, CodingKey {
        case token
        case deviceID = "device_id"
    }
}

private struct ProxyEngineConfigPayload: Encodable, Equatable {
    let agentIdentity: AgentIdentityPayload?
    let reportingEndpoint: String?
    let aikidoURL: String?
    let hostBundleID: String
    let caCertPEM: String?
    let caKeyPEM: String?

    private enum CodingKeys: String, CodingKey {
        case agentIdentity = "agent_identity"
        case reportingEndpoint = "reporting_endpoint"
        case aikidoURL = "aikido_url"
        case hostBundleID = "host_bundle_id"
        case caCertPEM = "ca_cert_pem"
        case caKeyPEM = "ca_key_pem"
    }

    var isEmpty: Bool {
        agentIdentity == nil
            && reportingEndpoint == nil
            && aikidoURL == nil
            && caCertPEM == nil
            && caKeyPEM == nil
    }
}

private struct MITMCASecrets: Equatable {
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
    private lazy var logger = Logger(
        subsystem: "com.aikido.endpoint.proxy.l4", category: "host-main")
    private lazy var sharedAccessGroup: String? = {
        let value = infoString(key: "AikidoL4SharedAccessGroup", fallback: "")
        return value.isEmpty ? nil : value
    }()

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
            case .cleanSecrets:
                cleanSecrets()
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

        let mitmCA = try loadOrCreateMITMCA()
        let engineConfigJSON = try Self.makeEngineConfigJSON(from: options, mitmCA: mitmCA)
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
        guard let manager = selectManager(from: managers) else {
            print("status: not-installed")
            return
        }

        if manager.connection.status != .disconnected && manager.connection.status != .invalid {
            log("stopping transparent proxy tunnel")
            manager.connection.stopVPNTunnel()
            waitUntilDisconnected(manager: manager, attempts: 40)
        }

        if options.cleanSecrets {
            cleanSecrets()
        }

        if options.removeProfile {
            let managersToRemove = matchingManagers(from: managers)
            if !managersToRemove.isEmpty {
                log("removing \(managersToRemove.count) saved transparent proxy manager(s)")
                try removeManagersFromPreferences(managersToRemove)
            }
            print("status: removed")
        } else {
            print("status: \(statusString(manager.connection.status))")
        }
    }

    private func status() throws {
        guard let manager = selectManager(from: try loadManagers()) else {
            print("status: not-installed")
            return
        }

        print("status: \(statusString(manager.connection.status))")
    }

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

    private static let secretAccount = "safechain-lib-l4-proxy-macos"
    private static let secretServiceKeyPEM = "tls-root-selfsigned-ca-key"
    private static let secretServiceCertPEM = "tls-root-selfsigned-ca-crt"
    private static let secretServiceKeys = [
        secretServiceKeyPEM,
        secretServiceCertPEM,
    ]

    private func cleanSecrets() {
        for key in Self.secretServiceKeys {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: key,
                kSecAttrAccount as String: Self.secretAccount,
                kSecUseDataProtectionKeychain as String: true,
            ]

            if let sharedAccessGroup {
                query[kSecAttrAccessGroup as String] = sharedAccessGroup
            }

            let status = SecItemDelete(query as CFDictionary)
            if status == errSecSuccess {
                log("deleted keychain secret: \(key)")
            } else if status != errSecItemNotFound {
                log("failed to delete keychain secret \(key): OSStatus \(status)")
            }
        }

        print("secrets: cleaned")
    }

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
            guard arguments.count == 1 else {
                throw CLIError.usage("`status` does not accept additional arguments")
            }
            return .status
        case "clean-secrets":
            guard arguments.count == 1 else {
                throw CLIError.usage("`clean-secrets` does not accept additional arguments")
            }
            return .cleanSecrets
        default:
            throw CLIError.usage("unknown command: \(first)")
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
            case "--clean-secrets":
                options.cleanSecrets = true
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
        mitmCA: MITMCASecrets
    ) throws -> String? {
        let agentIdentity: AgentIdentityPayload?
        if let token = options.agentToken, let deviceID = options.agentDeviceID {
            agentIdentity = AgentIdentityPayload(token: token, deviceID: deviceID)
        } else {
            agentIdentity = nil
        }

        let payload = ProxyEngineConfigPayload(
            agentIdentity: agentIdentity,
            reportingEndpoint: options.reportingEndpoint,
            aikidoURL: options.aikidoURL,
            hostBundleID: Bundle.main.bundleIdentifier ?? "com.aikido.endpoint.proxy.l4.dev",
            caCertPEM: mitmCA.certPEM,
            caKeyPEM: mitmCA.keyPEM
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(payload)
        guard let json = String(data: data, encoding: .utf8) else {
            throw CLIError.runtime("failed to encode transparent proxy config as UTF-8 JSON")
        }
        return json
    }

    private func loadOrCreateMITMCA() throws -> MITMCASecrets {
        let existingKey = try loadSecret(service: Self.secretServiceKeyPEM)
        let existingCert = try loadSecret(service: Self.secretServiceCertPEM)

        if let keyPEM = existingKey, let certPEM = existingCert {
            log("loaded MITM CA PEM from keychain")
            return MITMCASecrets(certPEM: certPEM, keyPEM: keyPEM)
        }

        if existingKey != nil || existingCert != nil {
            log("MITM CA keychain state incomplete; deleting partial CA material and regenerating")
            cleanSecrets()
        }

        let generated = try generateSelfSignedCAPEM()
        try storeSecret(service: Self.secretServiceKeyPEM, value: generated.keyPEM)
        try storeSecret(service: Self.secretServiceCertPEM, value: generated.certPEM)
        log("generated and stored new MITM CA PEM in keychain")
        return generated
    }

    private func loadSecret(service: String) throws -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.secretAccount,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        if let sharedAccessGroup {
            query[kSecAttrAccessGroup as String] = sharedAccessGroup
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw CLIError.runtime("keychain item for \(service) did not return Data")
            }
            guard let value = String(data: data, encoding: .utf8) else {
                throw CLIError.runtime("keychain item for \(service) was not valid UTF-8")
            }
            return value
        case errSecItemNotFound:
            return nil
        default:
            throw CLIError.runtime("failed to load keychain secret \(service): OSStatus \(status)")
        }
    }

    private func storeSecret(service: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw CLIError.runtime("failed to encode keychain secret \(service) as UTF-8")
        }

        var baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.secretAccount,
            kSecUseDataProtectionKeychain as String: true,
        ]

        if let sharedAccessGroup {
            baseQuery[kSecAttrAccessGroup as String] = sharedAccessGroup
        }

        let updateAttrs: [String: Any] = [
            kSecValueData as String: data
        ]

        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }

        if updateStatus != errSecItemNotFound {
            throw CLIError.runtime(
                "failed to update keychain secret \(service): OSStatus \(updateStatus)")
        }

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess {
            throw CLIError.runtime(
                "failed to add keychain secret \(service): OSStatus \(addStatus)")
        }
    }

    private func generateSelfSignedCAPEM() throws -> MITMCASecrets {
        let keyPEM = try runProcessCaptureStdout(
            launchPath: "/usr/bin/openssl",
            arguments: [
                "genpkey",
                "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:3072",
                "-outform", "PEM",
            ]
        )

        guard keyPEM.contains("BEGIN PRIVATE KEY") || keyPEM.contains("BEGIN RSA PRIVATE KEY")
        else {
            throw CLIError.runtime("generated CA private key PEM had unexpected format")
        }

        let certPEM = try runProcessCaptureStdout(
            launchPath: "/usr/bin/openssl",
            arguments: [
                "req",
                "-x509",
                "-new",
                "-sha256",
                "-days", "3650",
                "-key", "/dev/stdin",
                "-out", "/dev/stdout",
                "-subj", "/CN=Aikido Endpoint L4 Proxy Root CA/O=Aikido/OU=Endpoint/C=BE",
                "-addext", "basicConstraints=critical,CA:true,pathlen:0",
                "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid:always,issuer",
            ],
            stdin: keyPEM
        )

        guard certPEM.contains("BEGIN CERTIFICATE") else {
            throw CLIError.runtime("generated CA certificate PEM had unexpected format")
        }

        return MITMCASecrets(certPEM: certPEM, keyPEM: keyPEM)
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

    private func runProcess(launchPath: String, arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            throw CLIError.runtime("failed to launch \(launchPath): \(error.localizedDescription)")
        }

        process.waitUntilExit()

        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrText = String(data: stderrData, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            throw CLIError.runtime(
                "command failed: \(launchPath) \(arguments.joined(separator: " ")): \(stderrText.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }
    }

    private static func usage() -> String {
        """
        Usage:
          AikidoEndpointL4ProxyHost start [options]
          AikidoEndpointL4ProxyHost stop [options]
          AikidoEndpointL4ProxyHost status
          AikidoEndpointL4ProxyHost clean-secrets

        Commands:
          start          Install or update the transparent proxy profile and request that it starts.
          stop           Request that the transparent proxy tunnel stops.
          status         Show the current Network Extension status and saved engine config.
          clean-secrets  Delete proxy CA secrets from the keychain.

        Stop options:
          --remove-profile             Remove the saved Network Extension profile after stopping.
          --clean-secrets              Delete proxy CA secrets from the keychain.

        Start options:
          --reporting-endpoint URL   POST blocked-event reports to this absolute URL.
          --aikido-url URL           Override the Aikido app base URL used by the extension.
          --agent-token TOKEN        Agent token to forward to the extension config.
          --agent-device-id ID       Agent device identifier to forward to the extension config.
          --reset-profile            Remove the saved Network Extension profile before starting.
          --help                     Show this help text.

        Notes:
          - The transparent proxy extension is managed by macOS after `start`; this host process
            does not need to stay alive for the proxy to keep running.
          - Provide both `--agent-token` and `--agent-device-id` together or omit both.
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
