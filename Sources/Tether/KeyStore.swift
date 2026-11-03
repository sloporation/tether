import CryptoKit
import Foundation
import Security

/// Where pairing keys are kept, one per paired device.
public protocol TetherKeyStore: Sendable {
    func key(for peer: String) -> SymmetricKey?
    func setKey(_ key: SymmetricKey, for peer: String)
    func removeKey(for peer: String)
}

/// Keys in the Keychain, readable after the device's first unlock (so a sync
/// can run while it's locked).
/// Keys in the data protection keychain, readable after the device's first
/// unlock (so a sync can run while it's locked). On macOS that keychain needs
/// the app to have a `keychain-access-groups` entitlement, and its items
/// survive rebuilds and updates; without the entitlement (e.g. `swift test`)
/// keys fall back to the login keychain, whose items are tied to the exact
/// build that saved them.
public struct KeychainKeyStore: TetherKeyStore {
    public let service: String

    public init(service: String) {
        self.service = service
    }

    public func key(for peer: String) -> SymmetricKey? {
        for dataProtection in Self.keychains {
            var query = baseQuery(peer, dataProtection: dataProtection)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data {
                return SymmetricKey(data: data)
            }
        }
        return nil
    }

    public func setKey(_ key: SymmetricKey, for peer: String) {
        removeKey(for: peer)
        var status = errSecMissingEntitlement
        for dataProtection in Self.keychains {
            var item = baseQuery(peer, dataProtection: dataProtection)
            item[kSecValueData as String] = key.data
            if dataProtection {
                item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }
            status = SecItemAdd(item as CFDictionary, nil)
            if status != errSecMissingEntitlement { break }
        }
        assert(status == errSecSuccess, "Tether couldn't store a key in the Keychain (OSStatus \(status))")
    }

    public func removeKey(for peer: String) {
        for dataProtection in Self.keychains {
            SecItemDelete(baseQuery(peer, dataProtection: dataProtection) as CFDictionary)
        }
    }

    /// The data protection keychain, then (macOS only) the login keychain.
    private static var keychains: [Bool] {
        #if os(macOS)
        [true, false]
        #else
        [true]
        #endif
    }

    private func baseQuery(_ peer: String, dataProtection: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: peer,
        ]
        if dataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }
}

/// Keys in memory only, for tests and previews.
public final class MemoryKeyStore: TetherKeyStore, @unchecked Sendable {
    private var keys: [String: SymmetricKey] = [:]
    private let lock = NSLock()

    public init() {}

    public func key(for peer: String) -> SymmetricKey? {
        lock.withLock { keys[peer] }
    }

    public func setKey(_ key: SymmetricKey, for peer: String) {
        lock.withLock { keys[peer] = key }
    }

    public func removeKey(for peer: String) {
        lock.withLock { _ = keys.removeValue(forKey: peer) }
    }
}
