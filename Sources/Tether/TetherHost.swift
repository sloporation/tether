import CryptoKit
import Foundation
import Network
import Observation

/// The side that listens (the Mac): advertises itself with Bonjour, pairs new
/// clients once the person allows them, and hands each verified connection to
/// the app as a `TetherSession`.
@MainActor
@Observable
public final class TetherHost {
    /// A client that has paired (or been refused).
    public struct Peer: Codable, Identifiable, Equatable, Sendable {
        public var id: String
        public var name: String
        public var allowed = false
        public var refused = false
        public var lastSeen: Date?
    }

    /// A client asking to pair now. Show `code` and ask the person to check it
    /// matches the one on the client, then `allow` or `refuse`.
    public struct PairingRequest: Identifiable, Equatable, Sendable {
        public var id: String
        public var name: String
        public var code: String
    }

    public private(set) var peers: [Peer] = []
    public private(set) var pairingRequest: PairingRequest?
    /// Why clients can't reach this host, if they can't.
    public private(set) var problem: String?
    /// The port being listened on, once listening.
    public private(set) var port: UInt16?

    /// This host's id, made once and kept.
    public let hostID: String
    /// The name clients see, e.g. "Jacob's MacBook Pro".
    public let name: String
    /// Called with each verified connection. Return when the conversation is
    /// over; the session is closed afterwards.
    @ObservationIgnored public var onSession: (@MainActor (TetherSession) async -> Void)?

    private let configuration: TetherConfiguration
    private let keyStore: TetherKeyStore
    private let defaults: UserDefaults
    @ObservationIgnored private var listener: NWListener?
    @ObservationIgnored private var advertise = true
    @ObservationIgnored private var restarting = false
    @ObservationIgnored private var restartAgain = false
    /// Keys the running listener was started with: client id → key.
    @ObservationIgnored private var listeningKeys: [String: Data] = [:]
    /// Keys offered by clients pairing now, until allowed or refused.
    @ObservationIgnored private var offeredKeys: [String: SymmetricKey] = [:]

    public init(
        configuration: TetherConfiguration,
        name: String,
        keyStore: TetherKeyStore? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.configuration = configuration
        self.name = name
        self.keyStore = keyStore ?? KeychainKeyStore(service: configuration.keychainService + ".clients")
        self.defaults = defaults
        let idKey = configuration.defaultsKey("hostID")
        if let id = defaults.string(forKey: idKey) {
            hostID = id
        } else {
            hostID = UUID().uuidString
            defaults.set(hostID, forKey: idKey)
        }
        if let data = defaults.data(forKey: configuration.defaultsKey("peers")),
           let saved = try? JSONDecoder().decode([Peer].self, from: data) {
            // An allowed peer whose key is gone can't connect; drop it so it pairs again.
            let keys = self.keyStore
            peers = saved.filter { $0.refused || keys.key(for: $0.id) != nil }
        }
    }

    // MARK: Managing clients

    public func allow(_ id: String) {
        guard let key = offeredKeys.removeValue(forKey: id) else { return }
        keyStore.setKey(key, for: id)
        update(id) {
            $0.allowed = true
            $0.refused = false
        }
        if pairingRequest?.id == id { pairingRequest = nil }
        Task { await restart() }
    }

    public func refuse(_ id: String) {
        let wasAllowed = peer(id)?.allowed == true
        offeredKeys[id] = nil
        keyStore.removeKey(for: id)
        if peer(id) == nil, let request = pairingRequest, request.id == id {
            peers.append(Peer(id: id, name: request.name))
        }
        update(id) {
            $0.allowed = false
            $0.refused = true
        }
        if pairingRequest?.id == id { pairingRequest = nil }
        if wasAllowed { Task { await restart() } }
    }

    /// Removes a client entirely; it can pair again.
    public func forget(_ id: String) {
        let wasAllowed = peer(id)?.allowed == true
        peers.removeAll { $0.id == id }
        keyStore.removeKey(for: id)
        save()
        if wasAllowed { Task { await restart() } }
    }

    public func peer(_ id: String) -> Peer? { peers.first { $0.id == id } }

    // MARK: Listening

    /// Starts listening. `advertise: false` skips Bonjour (for tests).
    public func start(advertise: Bool = true) async {
        self.advertise = advertise
        if !(await listen(on: nil)) {
            problem = problem ?? "Other devices can't find this one."
        }
    }

    public func stop() {
        listener?.cancel()
        listener = nil
    }

    /// Listens again with the current keys (TLS keys are fixed when listening
    /// starts), on the same port if possible. Open connections carry on.
    func restart() async {
        restartAgain = true
        guard !restarting else { return }
        restarting = true
        defer { restarting = false }
        while restartAgain {
            restartAgain = false
            let port = self.port
            listener?.cancel()
            listener = nil
            if await listen(on: port.flatMap { NWEndpoint.Port(rawValue: $0) }) { continue }
            _ = await listen(on: nil)
        }
    }

    private func listen(on port: NWEndpoint.Port?) async -> Bool {
        let keys = peers.compactMap { peer -> (identity: String, key: SymmetricKey)? in
            guard peer.allowed, let key = keyStore.key(for: peer.id) else { return nil }
            return (peer.id, key)
        }
        let parameters = Wire.hostParameters(configuration, keys: keys)
        do {
            let listener = try port.map { try NWListener(using: parameters, on: $0) } ?? NWListener(using: parameters)
            if advertise {
                listener.service = NWListener.Service(
                    name: name,
                    type: configuration.serviceType,
                    txtRecord: NWTXTRecord(["host": hostID]).data
                )
            }
            listener.newConnectionHandler = { [weak self] connection in
                Task { @MainActor in await self?.serve(WireConnection(connection)) }
            }
            self.listener = listener
            return await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                let resumed = Flag()
                listener.stateUpdateHandler = { [weak self] state in
                    Task { @MainActor in
                        let ok: Bool
                        switch state {
                        case .ready:
                            self?.port = listener.port?.rawValue
                            self?.listeningKeys = Dictionary(keys.map { ($0.identity, $0.key.data) }, uniquingKeysWith: { a, _ in a })
                            self?.problem = nil
                            ok = true
                        case .failed(let error):
                            self?.problem = "Other devices can't find this one: \(error.localizedDescription)"
                            ok = false
                        case .cancelled:
                            ok = false
                        default:
                            return
                        }
                        if !resumed.value {
                            resumed.value = true
                            continuation.resume(returning: ok)
                        }
                    }
                }
                listener.start(queue: .main)
            }
        } catch {
            problem = "Other devices can't find this one: \(error.localizedDescription)"
            return false
        }
    }

    private func serve(_ wire: WireConnection) async {
        do {
            try await wire.start()
        } catch {
            return
        }
        do {
            let challenge = Pairing.challenge()
            try await wire.send(Wire.Greeting(challenge: challenge, host: hostID, name: name))
            let request = try await wire.receive(Wire.Request.self)
            switch request.op {
            case .pair:
                try await pair(request, over: wire)
                wire.cancel()
            case .hello:
                guard let session = try await hello(request, challenge: challenge, over: wire) else {
                    wire.cancel()
                    return
                }
                await onSession?(session)
                session.close()
            case .status:
                // Over the pairing identity: does this host still know the client?
                // Answers yes or no only; no session is opened.
                try await wire.send(statusReply(request, challenge: challenge))
                wire.cancel()
            case .unpair:
                // The client forgot this host; forget it here too.
                let reply = statusReply(request, challenge: challenge)
                if reply.ok, let id = request.client { forget(id) }
                try await wire.send(Wire.Reply(ok: true))
                wire.cancel()
            case .reveal:
                wire.cancel()
            }
        } catch {
            wire.cancel()
        }
    }

    /// A client pairing: its commitment, this host's half, its half; then both
    /// show the code, and the client waits, connected, to be allowed or refused.
    private func pair(_ first: Wire.Request, over wire: WireConnection) async throws {
        guard let id = first.client, !id.isEmpty, let commitment = first.commitment else {
            try await wire.send(Wire.Reply(ok: false, why: "The other device sent something unexpected."))
            return
        }
        if peer(id)?.refused == true {
            try await wire.send(Wire.Reply(ok: false, why: "\(name) doesn't allow this device. Forget it there to try again."))
            return
        }
        let mine = Curve25519.KeyAgreement.PrivateKey()
        let hostKey = mine.publicKey.rawRepresentation
        try await wire.send(Wire.Reply(ok: true, key: hostKey))
        let reveal = try await wire.receive(Wire.Request.self)
        guard reveal.op == .reveal, let clientKey = reveal.key, Pairing.commitment(to: clientKey) == commitment,
              let agreed = try? Pairing.agree(mine, with: clientKey, clientKey: clientKey, hostKey: hostKey, label: configuration.label)
        else {
            try await wire.send(Wire.Reply(ok: false, why: "The other device sent something unexpected."))
            return
        }
        let clientName = first.name ?? "Device"
        offeredKeys[id] = agreed.key
        pairingRequest = PairingRequest(id: id, name: clientName, code: agreed.code)
        if peer(id) != nil { update(id) { $0.name = clientName } }
        defer {
            if pairingRequest?.id == id, pairingRequest?.code == agreed.code {
                pairingRequest = nil
                offeredKeys[id] = nil
            }
        }
        try await wire.send(Wire.Reply(ok: true, waiting: true))

        // Wait for the person's answer while the client stays connected.
        let gone = Flag()
        Task { @MainActor in
            _ = try? await wire.receive(exactly: 1)
            gone.value = true
        }
        let deadline = Date.now.addingTimeInterval(10 * 60)
        while !gone.value, Date.now < deadline {
            if let peer = peer(id), peer.refused {
                try await wire.send(Wire.Reply(ok: false, why: "\(name) didn't allow this device."))
                return
            }
            if let peer = peer(id), peer.allowed, keyStore.key(for: id)?.data == agreed.key.data {
                if listeningKeys[id] == agreed.key.data {      // listening with its key now
                    if peer.name != clientName { update(id) { $0.name = clientName } }
                    try await wire.send(Wire.Reply(ok: true))
                    return
                }
            } else if pairingRequest?.id == id, pairingRequest?.code != agreed.code {
                return      // pairing again on another connection
            }
            try await Task.sleep(for: .milliseconds(250))
        }
        try? await wire.send(Wire.Reply(ok: false, why: "\(name) didn't answer."))
    }

    private func statusReply(_ request: Wire.Request, challenge: Data) -> Wire.Reply {
        guard let id = request.client, let proof = request.proof, let peer = peer(id), peer.allowed,
              let key = keyStore.key(for: id),
              Pairing.check(proof, challenge: challenge, client: id, key: key)
        else {
            return Wire.Reply(ok: false, unpaired: true)
        }
        return Wire.Reply(ok: true)
    }

    /// A paired client saying hello, proving who it is with its key.
    private func hello(_ request: Wire.Request, challenge: Data, over wire: WireConnection) async throws -> TetherSession? {
        guard let id = request.client, let proof = request.proof, let peer = peer(id), peer.allowed,
              let key = keyStore.key(for: id),
              Pairing.check(proof, challenge: challenge, client: id, key: key)
        else {
            try await wire.send(Wire.Reply(ok: false, why: "\(name) doesn't know this device.", unpaired: true))
            return nil
        }
        update(id) {
            $0.lastSeen = .now
            if let name = request.name { $0.name = name }
        }
        try await wire.send(Wire.Reply(ok: true))
        return TetherSession(wire: wire, peerID: id, peerName: peer.name)
    }

    private func update(_ id: String, _ change: (inout Peer) -> Void) {
        if peer(id) == nil, let request = pairingRequest, request.id == id {
            peers.append(Peer(id: id, name: request.name))
        }
        guard let index = peers.firstIndex(where: { $0.id == id }) else { return }
        change(&peers[index])
        save()
    }

    private func save() {
        defaults.set(try? JSONEncoder().encode(peers), forKey: configuration.defaultsKey("peers"))
    }
}

@MainActor
final class Flag {
    var value = false
}
