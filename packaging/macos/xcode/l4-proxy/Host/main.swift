import Darwin
import Foundation
import NetworkExtension
import OSLog

private enum HostCommand {
    case start(StartOptions)
    case stop
    case status
    case help
}

private struct StartOptions {
    var reportingEndpoint: String?
    var aikidoURL: String?
    var agentToken: String?
    var agentDeviceID: String?
    var useVPNSharedIdentity = false
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
    let useVPNSharedIdentity: Bool

    private enum CodingKeys: String, CodingKey {
        case agentIdentity = "agent_identity"
        case reportingEndpoint = "reporting_endpoint"
        case aikidoURL = "aikido_url"
        case useVPNSharedIdentity = "use_vpn_shared_identity"
    }

    var isEmpty: Bool {
        agentIdentity == nil && reportingEndpoint == nil && aikidoURL == nil
            && useVPNSharedIdentity == false
    }
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

private final class TransparentProxyHostCLI {
    private let extensionBundleId = "com.aikido.endpoint.proxy.l4.extension"
    private let managerDescription = "Aikido Endpoint L4 Transparent Proxy"
    private let managerServerAddress = "127.0.0.1"
    private let logSubsystem = "com.aikido.endpoint.proxy.l4"
    private lazy var logger = Logger(subsystem: logSubsystem, category: "host-cli")

    func run(arguments: [String]) -> Int32 {
        do {
            let command = try Self.parse(arguments: arguments)

            switch command {
            case .start(let options):
                try start(options: options)
                return EXIT_SUCCESS
            case .stop:
                try stop()
                return EXIT_SUCCESS
            case .status:
                try status()
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
        let engineConfigJSON = try Self.makeEngineConfigJSON(from: options)
        let existingManagers = try loadManagers()

        if options.resetProfile {
            let managersToRemove = matchingManagers(from: existingManagers)
            if !managersToRemove.isEmpty {
                log("removing \(managersToRemove.count) saved transparent proxy manager(s)")
                try removeManagersFromPreferences(managersToRemove)
            }
        }

        let manager = try prepareManager(existingManagers: options.resetProfile ? [] : existingManagers, engineConfigJSON: engineConfigJSON)

        if shouldRestartTunnel(manager: manager, expectedEngineConfigJSON: engineConfigJSON) {
            log("configuration changed while proxy was active; restarting tunnel")
            manager.connection.stopVPNTunnel()
            waitUntilDisconnected(manager: manager, attempts: 40)
        } else if isActive(manager.connection.status) {
            print("status: \(statusString(manager.connection.status))")
            if let engineConfigJSON {
                print("config: \(engineConfigJSON)")
            }
            return
        }

        do {
            try manager.connection.startVPNTunnel()
            log("transparent proxy start requested")
        } catch {
            throw CLIError.runtime("failed to start transparent proxy: \(error.localizedDescription)")
        }

        let status = waitForSteadyState(manager: manager, attempts: 20)
        print("status: \(statusString(status))")
        if let engineConfigJSON {
            print("config: \(engineConfigJSON)")
        }
    }

    private func stop() throws {
        guard let manager = selectManager(from: try loadManagers()) else {
            print("status: not-installed")
            return
        }

        if manager.connection.status == .disconnected || manager.connection.status == .invalid {
            print("status: \(statusString(manager.connection.status))")
            return
        }

        log("stopping transparent proxy tunnel")
        manager.connection.stopVPNTunnel()
        let status = waitUntilDisconnected(manager: manager, attempts: 40)
        print("status: \(statusString(status))")
    }

    private func status() throws {
        guard let manager = selectManager(from: try loadManagers()) else {
            print("status: not-installed")
            return
        }

        print("status: \(statusString(manager.connection.status))")
        if
            let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
            let engineConfigJSON = proto.providerConfiguration?["engineConfigJson"] as? String
        {
            print("config: \(engineConfigJSON)")
        }
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

    private func prepareManager(
        existingManagers: [NETransparentProxyManager],
        engineConfigJSON: String?
    ) throws -> NETransparentProxyManager {
        let existingManager = selectManager(from: existingManagers)
        let manager = existingManager ?? NETransparentProxyManager()
        let changed = configure(manager: manager, engineConfigJSON: engineConfigJSON)

        if changed || existingManager == nil {
            log(existingManager == nil ? "saving new proxy manager" : "saving updated proxy manager")
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

    private func selectManager(from managers: [NETransparentProxyManager]) -> NETransparentProxyManager? {
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

    private func matchingManagers(from managers: [NETransparentProxyManager]) -> [NETransparentProxyManager] {
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
    private func waitUntilDisconnected(manager: NETransparentProxyManager, attempts: Int) -> NEVPNStatus {
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

    private func waitForSteadyState(manager: NETransparentProxyManager, attempts: Int) -> NEVPNStatus {
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

    private func log(_ message: String) {
        logger.info("\(message, privacy: .public)")
    }

    private func logError(_ prefix: String, _ error: Error) {
        let ns = error as NSError
        logger.error(
            "\(prefix, privacy: .public): domain=\(ns.domain, privacy: .public) code=\(ns.code, privacy: .public) description=\(ns.localizedDescription, privacy: .public)"
        )
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
            guard arguments.count == 1 else {
                throw CLIError.usage("`stop` does not accept additional arguments")
            }
            return .stop
        case "status":
            guard arguments.count == 1 else {
                throw CLIError.usage("`status` does not accept additional arguments")
            }
            return .status
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
                options.reportingEndpoint = try consumeValue(flag: argument, arguments: arguments, index: &index)
                try validateAbsoluteURL(options.reportingEndpoint, flag: argument)
            case "--aikido-url":
                options.aikidoURL = try consumeValue(flag: argument, arguments: arguments, index: &index)
                try validateAbsoluteURL(options.aikidoURL, flag: argument)
            case "--agent-token":
                options.agentToken = try consumeValue(flag: argument, arguments: arguments, index: &index)
            case "--agent-device-id":
                options.agentDeviceID = try consumeValue(flag: argument, arguments: arguments, index: &index)
            case "--use-vpn-shared-identity":
                options.useVPNSharedIdentity = true
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

    private static func makeEngineConfigJSON(from options: StartOptions) throws -> String? {
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
            useVPNSharedIdentity: options.useVPNSharedIdentity
        )

        guard !payload.isEmpty else {
            return nil
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(payload)
        guard let json = String(data: data, encoding: .utf8) else {
            throw CLIError.runtime("failed to encode transparent proxy config as UTF-8 JSON")
        }
        return json
    }

    private static func usage() -> String {
        """
        Usage:
          AikidoEndpointL4ProxyHost start [options]
          AikidoEndpointL4ProxyHost stop
          AikidoEndpointL4ProxyHost status

        Commands:
          start    Install or update the transparent proxy profile and request that it starts.
          stop     Request that the transparent proxy tunnel stops.
          status   Show the current Network Extension status and saved engine config.

        Start options:
          --reporting-endpoint URL   POST blocked-event reports to this absolute URL.
          --aikido-url URL           Override the Aikido app base URL used by the extension.
          --agent-token TOKEN        Agent token to forward to the extension config.
          --agent-device-id ID       Agent device identifier to forward to the extension config.
          --use-vpn-shared-identity  Use the managed identity from com.apple.managed.vpn.shared.
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

let arguments = Array(CommandLine.arguments.dropFirst())
let exitCode = TransparentProxyHostCLI().run(arguments: arguments)
exit(exitCode)
