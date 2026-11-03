import CryptoKit
import Foundation

/// What makes one app's tether separate from another's: its Bonjour service
/// type, and a label used for the pairing identity, key derivation, and where
/// keys and peers are stored.
public struct TetherConfiguration: Sendable {
    /// Bonjour service type, e.g. `"_liftbro._tcp"`. List it under
    /// `NSBonjourServices` in both apps' Info.plist.
    public var serviceType: String
    /// Short, stable name for the app, e.g. `"liftbro"`. Changing it forgets
    /// every pairing.
    public var label: String

    public init(serviceType: String, label: String) {
        self.serviceType = serviceType
        self.label = label
    }

    /// TLS identity used while pairing. Its key isn't secret: pairing is made
    /// safe by the code both devices show, not by TLS.
    var pairingIdentity: String { "\(label)-pairing" }
    var pairingKey: SymmetricKey { SymmetricKey(data: Data(SHA256.hash(data: Data(pairingIdentity.utf8)))) }

    var keychainService: String { "tether.\(label)" }
    func defaultsKey(_ name: String) -> String { "tether.\(label).\(name)" }
}

public enum TetherError: LocalizedError, Equatable {
    /// The other side said no, with its reason.
    case refused(String)
    /// The host doesn't know this device (or its key) any more: pair again.
    case unpaired
    /// A different host answered than the one asked for.
    case unexpectedHost
    case closed
    case tooBig

    public var errorDescription: String? {
        switch self {
        case .refused(let why): why
        case .unpaired: "This device isn't paired any more. Pair again."
        case .unexpectedHost: "A different device answered."
        case .closed: "The connection was lost."
        case .tooBig: "The other device sent something unexpected."
        }
    }
}
