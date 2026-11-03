import CryptoKit
import Foundation
import Network
import Testing
@testable import Tether

private let configuration = TetherConfiguration(serviceType: "_tethertest._tcp", label: "tethertest")

private func freshDefaults() -> UserDefaults {
    let name = "tether.tests.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: name)!
    defaults.removePersistentDomain(forName: name)
    return defaults
}

private struct Ping: Codable, Equatable { var text: String }

@Suite struct PairingCryptoTests {
    @Test func bothSidesAgreeOnKeyAndCode() throws {
        let client = Curve25519.KeyAgreement.PrivateKey()
        let host = Curve25519.KeyAgreement.PrivateKey()
        let clientKey = client.publicKey.rawRepresentation
        let hostKey = host.publicKey.rawRepresentation
        let a = try Pairing.agree(client, with: hostKey, clientKey: clientKey, hostKey: hostKey, label: "x")
        let b = try Pairing.agree(host, with: clientKey, clientKey: clientKey, hostKey: hostKey, label: "x")
        #expect(a.key.data == b.key.data)
        #expect(a.code == b.code)
        #expect(a.code.count == 7)
    }

    @Test func proofOnlyChecksWithTheRightKeyAndClient() {
        let key = SymmetricKey(size: .bits256)
        let challenge = Pairing.challenge()
        let proof = Pairing.proof(challenge: challenge, client: "phone", key: key)
        #expect(Pairing.check(proof, challenge: challenge, client: "phone", key: key))
        #expect(!Pairing.check(proof, challenge: challenge, client: "other", key: key))
        #expect(!Pairing.check(proof, challenge: Pairing.challenge(), client: "phone", key: key))
        #expect(!Pairing.check(proof, challenge: challenge, client: "phone", key: SymmetricKey(size: .bits256)))
    }
}

@Suite struct KeychainTests {
    @Test func storesReadsAndRemovesAKey() {
        let store = KeychainKeyStore(service: "tether.tests.\(UUID().uuidString)")
        let key = SymmetricKey(size: .bits256)
        store.setKey(key, for: "peer")
        #expect(store.key(for: "peer")?.data == key.data)
        store.removeKey(for: "peer")
        #expect(store.key(for: "peer") == nil)
    }
}

@MainActor
@Suite(.serialized) struct LoopbackTests {
    private func makeHost() async throws -> (TetherHost, NWEndpoint) {
        let host = TetherHost(configuration: configuration, name: "Test Mac", keyStore: MemoryKeyStore(), defaults: freshDefaults())
        await host.start(advertise: false)
        let port = try #require(host.port)
        return (host, .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!))
    }

    /// Where the host is listening now (it can change port when it restarts
    /// with a new client's key; real clients find it again through Bonjour).
    private func currentEndpoint(of host: TetherHost) throws -> NWEndpoint {
        .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: try #require(host.port))!)
    }

    private func makeClient() -> TetherClient {
        TetherClient(configuration: configuration, name: "Test iPhone", keyStore: MemoryKeyStore(), defaults: freshDefaults())
    }

    /// Pairs, answering on the host with `allow` (or refuse).
    private func pair(_ client: TetherClient, with host: TetherHost, at endpoint: NWEndpoint, allow: Bool) async throws -> (String?, String?) {
        var clientCode: String?
        let pairing = Task { @MainActor in
            try await client.pair(endpoint: endpoint) { clientCode = $0 }
        }
        var hostCode: String?
        for _ in 0..<200 {
            if let request = host.pairingRequest {
                hostCode = request.code
                #expect(request.name == "Test iPhone")
                if allow { host.allow(request.id) } else { host.refuse(request.id) }
                break
            }
            try await Task.sleep(for: .milliseconds(25))
        }
        _ = try await pairing.value
        return (clientCode, hostCode)
    }

    @Test func pairThenExchangeMessages() async throws {
        let (host, endpoint) = try await makeHost()
        defer { host.stop() }
        host.onSession = { session in
            guard let ping = try? await session.receive(Ping.self) else { return }
            try? await session.send(Ping(text: "pong: \(ping.text) from \(session.peerName)"))
        }
        let client = makeClient()

        let (clientCode, hostCode) = try await pair(client, with: host, at: endpoint, allow: true)
        #expect(clientCode != nil)
        #expect(clientCode == hostCode)
        #expect(client.isPaired(host.hostID))
        #expect(host.peer(client.clientID)?.allowed == true)

        let session = try await client.connect(endpoint: try currentEndpoint(of: host), hostID: host.hostID)
        defer { session.close() }
        try await session.send(Ping(text: "hi"))
        let reply = try await session.receive(Ping.self)
        #expect(reply.text == "pong: hi from Test iPhone")
        #expect(host.peer(client.clientID)?.lastSeen != nil)
    }

    @Test func sendsRawBytesAfterAMessage() async throws {
        let (host, endpoint) = try await makeHost()
        defer { host.stop() }
        let file = Data((0..<3_000_000).map { UInt8($0 % 251) })
        host.onSession = { session in
            try? await session.send(Ping(text: "\(file.count)"))
            try? await session.send(bytes: file)
            _ = try? await session.receive(Ping.self)
        }
        let client = makeClient()
        _ = try await pair(client, with: host, at: endpoint, allow: true)
        let session = try await client.connect(endpoint: try currentEndpoint(of: host), hostID: host.hostID)
        defer { session.close() }
        let size = try #require(Int64(try await session.receive(Ping.self).text))
        let url = FileManager.default.temporaryDirectory.appending(path: "tether-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: url) }
        try await session.receiveFile(size: size, to: url)
        #expect(try Data(contentsOf: url) == file)
        try await session.send(Ping(text: "done"))
    }

    @Test func refusedClientIsNotPaired() async throws {
        let (host, endpoint) = try await makeHost()
        defer { host.stop() }
        let client = makeClient()

        await #expect(throws: TetherError.self) {
            _ = try await pair(client, with: host, at: endpoint, allow: false)
        }
        #expect(!client.isPaired(host.hostID))
        #expect(host.peer(client.clientID)?.refused == true)

        // A refused client can't pair again until it's forgotten on the host.
        await #expect(throws: TetherError.self) {
            try await client.pair(endpoint: endpoint) { _ in }
        }
    }

    @Test func unpairingFromTheClientRemovesItFromTheHost() async throws {
        let (host, endpoint) = try await makeHost()
        defer { host.stop() }
        let client = makeClient()
        _ = try await pair(client, with: host, at: endpoint, allow: true)
        #expect(host.peer(client.clientID)?.allowed == true)

        // unpair(from:) finds the host through Bonjour; tests call the same
        // request over the loopback endpoint.
        try await client.sendUnpair(endpoint: try currentEndpoint(of: host), hostID: host.hostID)
        client.forget(host.hostID)
        #expect(host.peer(client.clientID) == nil)
        #expect(!client.isPaired(host.hostID))
    }

    @Test func forgottenClientIsToldToPairAgain() async throws {
        let (host, endpoint) = try await makeHost()
        defer { host.stop() }
        let client = makeClient()
        _ = try await pair(client, with: host, at: endpoint, allow: true)

        host.forget(client.clientID)
        try await Task.sleep(for: .milliseconds(300))      // listener restarts without its key

        let current = try currentEndpoint(of: host)
        await #expect(throws: TetherError.unpaired) {
            _ = try await client.connect(endpoint: current, hostID: host.hostID)
        }
        // …and it forgets the host, so the app can offer to pair again.
        #expect(!client.isPaired(host.hostID))
    }
}
