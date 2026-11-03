import Foundation

/// An authenticated, encrypted connection to a paired device. The app defines
/// what it says: any `Codable` messages, sent and received in turn.
public final class TetherSession: Sendable {
    /// The device at the other end.
    public let peerID: String
    public let peerName: String

    private let wire: WireConnection

    init(wire: WireConnection, peerID: String, peerName: String) {
        self.wire = wire
        self.peerID = peerID
        self.peerName = peerName
    }

    public func send<Message: Encodable>(_ message: Message) async throws {
        try await wire.send(message)
    }

    public func receive<Message: Decodable>(_ type: Message.Type) async throws -> Message {
        try await wire.receive(type)
    }

    public func close() {
        wire.cancel()
    }
}
