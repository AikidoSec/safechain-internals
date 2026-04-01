import Foundation
import NetworkExtension
import OSLog

private let logger = Logger(
    subsystem: "com.aikido.endpoint.proxy.l4",
    category: "extension-main"
)

logger.info("starting system extension mode")
NEProvider.startSystemExtensionMode()
dispatchMain()
