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

    /// Sends bytes as they are, without a length or JSON: for something
    /// large, such as a file, after a message that says how many bytes follow.
    public func send(bytes: Data) async throws {
        try await wire.send(bytes)
    }

    /// Receives `size` bytes sent with `send(bytes:)` into a file, a piece at
    /// a time, calling `progress` with how many have arrived.
    public func receiveFile(size: Int64, to url: URL, progress: @Sendable (Int64) -> Void = { _ in }) async throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        var received: Int64 = 0
        while received < size {
            let piece = try await wire.receive(upTo: Int(min(size - received, 1 << 20)))
            try handle.write(contentsOf: piece)
            received += Int64(piece.count)
            progress(received)
        }
    }

    public func close() {
        wire.cancel()
    }
}
