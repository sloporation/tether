import CryptoKit
import Foundation
import Network
import Observation

/// The side that connects (the iPhone): finds hosts with Bonjour, pairs with
/// one once (both show a code), then opens `TetherSession`s to it.
@MainActor
@Observable
public final class TetherClient {
    /// A host seen on the local network now.
    public struct Host: Identifiable, Hashable, Sendable {
        public var id: String
        public var name: String
        public var endpoint: NWEndpoint
    }

    /// A host this device has paired with.
    public struct PairedHost: Codable, Identifiable, Equatable, Sendable {
        public var id: String
        public var name: String
        public var lastConnected: Date?
    }

    public private(set) var discovered: [Host] = []
    public private(set) var paired: [PairedHost] = []
    public private(set) var isBrowsing = false
    /// Why browsing failed, if it did (e.g. local network access denied).
    public private(set) var problem: String?

    /// This device's id, made once and kept.
    public let clientID: String
    /// The name hosts see, e.g. "Jacob's iPhone".
    public let name: String

    private let configuration: TetherConfiguration
    private let keyStore: TetherKeyStore
    private let defaults: UserDefaults
    @ObservationIgnored private var browser: NWBrowser?

    public init(
        configuration: TetherConfiguration,
        name: String,
        keyStore: TetherKeyStore? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.configuration = configuration
        self.name = name
        self.keyStore = keyStore ?? KeychainKeyStore(service: configuration.keychainService + ".hosts")
        self.defaults = defaults
        let idKey = configuration.defaultsKey("clientID")
        if let id = defaults.string(forKey: idKey) {
            clientID = id
        } else {
            clientID = UUID().uuidString
            defaults.set(clientID, forKey: idKey)
        }
        if let data = defaults.data(forKey: configuration.defaultsKey("hosts")),
           let saved = try? JSONDecoder().decode([PairedHost].self, from: data) {
            paired = saved.filter { self.keyStore.key(for: $0.id) != nil }
        }
    }

    public func isPaired(_ hostID: String) -> Bool {
        paired.contains { $0.id == hostID } && keyStore.key(for: hostID) != nil
    }

    /// Paired hosts that are on the network now.
    public var reachablePairedHosts: [Host] {
        discovered.filter { isPaired($0.id) }
    }

    // MARK: Browsing

    public func startBrowsing() {
        guard browser == nil else { return }
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: configuration.serviceType, domain: nil), using: .tcp)
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let hosts = results.compactMap { result -> Host? in
                guard case .bonjour(let txt) = result.metadata, let id = txt["host"] else { return nil }
                guard case .service(let name, _, _, _) = result.endpoint else { return nil }
                return Host(id: id, name: name, endpoint: result.endpoint)
            }
            Task { @MainActor in self?.discovered = hosts }
        }
        browser.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                switch state {
                case .ready: self?.problem = nil
                case .failed(let error), .waiting(let error):
                    self?.problem = "Can't look for other devices: \(error.localizedDescription)"
                default: break
                }
            }
        }
        self.browser = browser
        isBrowsing = true
        browser.start(queue: .main)
    }

    public func stopBrowsing() {
        browser?.cancel()
        browser = nil
        isBrowsing = false
        discovered = []
    }

    // MARK: Pairing

    /// Pairs with a host. `code` is called with the code to show, which the
    /// host shows too; this returns once the host has allowed this device.
    public func pair(with host: Host, code: @MainActor (String) -> Void) async throws {
        try await pair(endpoint: host.endpoint, code: code)
    }

    /// Pairs with a host at an endpoint (tests connect without Bonjour).
    public func pair(endpoint: NWEndpoint, code: @MainActor (String) -> Void) async throws {
        let wire = WireConnection(NWConnection(to: endpoint, using: Wire.pairingParameters(configuration)))
        defer { wire.cancel() }
        try await wire.start()
        let greeting = try await wire.receive(Wire.Greeting.self)

        let mine = Curve25519.KeyAgreement.PrivateKey()
        let clientKey = mine.publicKey.rawRepresentation
        try await wire.send(Wire.Request(op: .pair, client: clientID, name: name, commitment: Pairing.commitment(to: clientKey)))
        let offer = try await wire.receive(Wire.Reply.self)
        guard offer.ok, let hostKey = offer.key else { throw TetherError.refused(offer.why ?? "\(greeting.name) said no.") }
        let agreed = try Pairing.agree(mine, with: hostKey, clientKey: clientKey, hostKey: hostKey, label: configuration.label)
        try await wire.send(Wire.Request(op: .reveal, key: clientKey))
        let asking = try await wire.receive(Wire.Reply.self)
        guard asking.ok else { throw TetherError.refused(asking.why ?? "\(greeting.name) said no.") }
        code(agreed.code)
        let answer = try await wire.receive(Wire.Reply.self)
        guard answer.ok else { throw TetherError.refused(answer.why ?? "\(greeting.name) didn't allow this device.") }

        keyStore.setKey(agreed.key, for: greeting.host)
        paired.removeAll { $0.id == greeting.host }
        paired.append(PairedHost(id: greeting.host, name: greeting.name))
        save()
    }

    /// Forgets a host, and first tells it to forget this device if it's on
    /// the network now (otherwise it's told next time this device connects
    /// and is turned away, or the host's user removes it there).
    public func unpair(from hostID: String) async {
        if let host = discovered.first(where: { $0.id == hostID }) {
            try? await sendUnpair(endpoint: host.endpoint, hostID: hostID)
        }
        forget(hostID)
    }

    /// Asks the host at `endpoint` to forget this device.
    func sendUnpair(endpoint: NWEndpoint, hostID: String) async throws {
        guard let key = keyStore.key(for: hostID) else { return }
        let wire = WireConnection(NWConnection(to: endpoint, using: Wire.pairingParameters(configuration)))
        defer { wire.cancel() }
        try await wire.start(timeout: .seconds(5))
        let greeting = try await wire.receive(Wire.Greeting.self)
        guard greeting.host == hostID else { return }
        try await wire.send(Wire.Request(
            op: .unpair, client: clientID,
            proof: Pairing.proof(challenge: greeting.challenge, client: clientID, key: key)
        ))
        _ = try await wire.receive(Wire.Reply.self)
    }

    /// Forgets a host on this device only.
    public func forget(_ hostID: String) {
        paired.removeAll { $0.id == hostID }
        keyStore.removeKey(for: hostID)
        save()
    }

    // MARK: Connecting

    /// Opens a session with a paired host. Throws `.unpaired` if the host no
    /// longer knows this device (it's forgotten here too; pair again).
    public func connect(to host: Host) async throws -> TetherSession {
        try await connect(endpoint: host.endpoint, hostID: host.id)
    }

    public func connect(endpoint: NWEndpoint, hostID: String) async throws -> TetherSession {
        do {
            return try await open(endpoint: endpoint, hostID: hostID)
        } catch TetherError.unpaired {
            throw TetherError.unpaired
        } catch {
            // The TLS handshake fails when the host no longer has this device's
            // key, before it can say so. Ask over the pairing channel.
            if await isStillPaired(endpoint: endpoint, hostID: hostID) == false {
                forget(hostID)
                throw TetherError.unpaired
            }
            throw error
        }
    }

    /// Whether the host still knows this device: `nil` if it couldn't be asked.
    func isStillPaired(endpoint: NWEndpoint, hostID: String) async -> Bool? {
        guard let key = keyStore.key(for: hostID) else { return false }
        let wire = WireConnection(NWConnection(to: endpoint, using: Wire.pairingParameters(configuration)))
        defer { wire.cancel() }
        do {
            try await wire.start()
            let greeting = try await wire.receive(Wire.Greeting.self)
            guard greeting.host == hostID else { return nil }
            try await wire.send(Wire.Request(
                op: .status, client: clientID,
                proof: Pairing.proof(challenge: greeting.challenge, client: clientID, key: key)
            ))
            let reply = try await wire.receive(Wire.Reply.self)
            return reply.unpaired == true ? false : (reply.ok ? true : nil)
        } catch {
            return nil
        }
    }

    private func open(endpoint: NWEndpoint, hostID: String) async throws -> TetherSession {
        guard let key = keyStore.key(for: hostID) else { throw TetherError.unpaired }
        let wire = WireConnection(NWConnection(to: endpoint, using: Wire.clientParameters(identity: clientID, key: key)))
        do {
            try await wire.start()
            // A host that no longer has this device's key fails the TLS
            // handshake, which can stall; don't wait on it forever.
            let watchdog = Task {
                try await Task.sleep(for: .seconds(10))
                wire.cancel()       // the receive below then fails
            }
            defer { watchdog.cancel() }
            let greeting = try await wire.receive(Wire.Greeting.self)
            guard greeting.host == hostID else { throw TetherError.unexpectedHost }
            try await wire.send(Wire.Request(
                op: .hello, client: clientID, name: name,
                proof: Pairing.proof(challenge: greeting.challenge, client: clientID, key: key)
            ))
            let reply = try await wire.receive(Wire.Reply.self)
            if reply.unpaired == true {
                forget(hostID)
                throw TetherError.unpaired
            }
            guard reply.ok else { throw TetherError.refused(reply.why ?? "\(greeting.name) said no.") }
            if let index = paired.firstIndex(where: { $0.id == hostID }) {
                paired[index].name = greeting.name
                paired[index].lastConnected = .now
                save()
            }
            return TetherSession(wire: wire, peerID: hostID, peerName: greeting.name)
        } catch {
            wire.cancel()
            throw error
        }
    }

    private func save() {
        defaults.set(try? JSONEncoder().encode(paired), forKey: configuration.defaultsKey("hosts"))
    }
}

