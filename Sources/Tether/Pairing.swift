import CryptoKit
import Foundation

/// Pairing a client with a host: each sends the other its half of a Curve25519
/// key agreement, and both derive the same key (for TLS) and the same six-digit
/// code. The person checks the codes match before allowing the client on the
/// host, so nobody in between can have swapped in their own halves. The client
/// commits to (sends a hash of) its half before seeing the host's, so someone
/// in the middle can't search for halves that happen to give matching codes.
enum Pairing {
    struct Agreed {
        var key: SymmetricKey
        var code: String            // "482 913"
    }

    /// The key and code from this side's private half and the other's public
    /// half. `clientKey` and `hostKey` are both public halves, in that order,
    /// whichever side this is.
    static func agree(
        _ mine: Curve25519.KeyAgreement.PrivateKey,
        with theirs: Data,
        clientKey: Data,
        hostKey: Data,
        label: String
    ) throws -> Agreed {
        let shared = try mine.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirs))
        let salt = clientKey + hostKey
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: Data("\(label) tether key".utf8), outputByteCount: 32)
        let digits = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: Data("\(label) tether code".utf8), outputByteCount: 4)
            .withUnsafeBytes { $0.reduce(UInt32(0)) { $0 << 8 | UInt32($1) } } % 1_000_000
        let code = String(format: "%06u", digits)
        return Agreed(key: key, code: code.prefix(3) + " " + code.suffix(3))
    }

    /// Proof that a hello comes from this client: the host's challenge and the
    /// client's id, signed with their shared key.
    static func proof(challenge: Data, client: String, key: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: challenge + Data(client.utf8), using: key))
    }

    static func check(_ proof: Data, challenge: Data, client: String, key: SymmetricKey) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: challenge + Data(client.utf8), using: key)
    }

    static func commitment(to key: Data) -> Data { Data(SHA256.hash(data: key)) }

    static func challenge() -> Data { SymmetricKey(size: .bits256).data }
}

extension SymmetricKey {
    var data: Data { withUnsafeBytes { Data($0) } }
}
