import CryptoKit
import Foundation
import Network

/// The bytes on the wire: TLS 1.2 with a pre-shared key per paired device (and
/// an ephemeral key exchange on top, so a key found later can't open traffic
/// recorded before). Each message is a 4-byte big-endian length and that much
/// JSON. The host speaks first, with a greeting.
enum Wire {
    /// The host's first message on every connection.
    struct Greeting: Codable {
        var challenge: Data
        var host: String
        var name: String
    }

    /// The client's handshake messages.
    struct Request: Codable {
        enum Op: String, Codable { case pair, reveal, hello }
        var op: Op
        var client: String?
        var name: String?
        var commitment: Data?       // pair: hash of the client's public half
        var key: Data?              // reveal: the client's public half
        var proof: Data?            // hello
    }

    /// The host's handshake answers.
    struct Reply: Codable {
        var ok: Bool
        var why: String?
        var key: Data?              // pair: the host's public half
        var waiting: Bool?          // reveal: now asking the person to allow it
        var unpaired: Bool?         // hello: unknown client; pair again
    }

    static func clientParameters(identity: String, key: SymmetricKey) -> NWParameters {
        tls(keys: [(identity, key)])
    }

    static func pairingParameters(_ configuration: TetherConfiguration) -> NWParameters {
        tls(keys: [(configuration.pairingIdentity, configuration.pairingKey)])
    }

    static func hostParameters(_ configuration: TetherConfiguration, keys: [(identity: String, key: SymmetricKey)]) -> NWParameters {
        tls(keys: [(configuration.pairingIdentity, configuration.pairingKey)] + keys)
    }

    private static func tls(keys: [(String, SymmetricKey)]) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv12)    // PSK in Network.framework is TLS 1.2
        sec_protocol_options_append_tls_ciphersuite(
            options, tls_ciphersuite_t(rawValue: UInt16(TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256))!)
        for (identity, key) in keys {
            sec_protocol_options_add_pre_shared_key(options, dispatchData(key.data), dispatchData(Data(identity.utf8)))
        }
        let parameters = NWParameters(tls: tls)
        parameters.includePeerToPeer = false
        return parameters
    }

    private static func dispatchData(_ data: Data) -> __DispatchData {
        data.withUnsafeBytes { DispatchData(bytes: $0) } as __DispatchData
    }

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    /// Upper bound for one message, so a bad length can't exhaust memory.
    static let maximumMessageSize = 64 << 20
}

/// One end of a connection, with async framed sends and receives.
final class WireConnection: @unchecked Sendable {
    let connection: NWConnection
    private let queue = DispatchQueue(label: "tether.wire")

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    /// Starts the connection and waits until it can be used.
    func start() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let once = Once(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: once.resume()
                case .failed(let error): once.resume(throwing: error)
                case .cancelled: once.resume(throwing: TetherError.closed)
                case .waiting(let error): once.resume(throwing: error)
                default: break
                }
            }
            connection.start(queue: queue)
        }
    }

    func cancel() { connection.cancel() }

    func send<T: Encodable>(_ message: T) async throws {
        let json = try Wire.encoder.encode(message)
        var length = UInt32(json.count).bigEndian
        try await send(Data(bytes: &length, count: 4) + json)
    }

    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }

    func receive<T: Decodable>(_ type: T.Type) async throws -> T {
        let header = try await receive(exactly: 4)
        let length = header.reduce(0) { $0 << 8 | Int($1) }
        guard length > 0, length < Wire.maximumMessageSize else { throw TetherError.tooBig }
        return try Wire.decoder.decode(T.self, from: try await receive(exactly: length))
    }

    func receive(exactly count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, data.count == count {
                    continuation.resume(returning: data)
                } else {
                    continuation.resume(throwing: TetherError.closed)
                }
            }
        }
    }
}

/// A continuation resumed at most once (the state handler keeps being called).
private final class Once: @unchecked Sendable {
    private var continuation: CheckedContinuation<Void, Error>?
    private let lock = NSLock()

    init(_ continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    func resume(throwing error: Error? = nil) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        if let error { continuation?.resume(throwing: error) } else { continuation?.resume() }
    }
}
