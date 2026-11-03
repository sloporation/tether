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
public struct KeychainKeyStore: TetherKeyStore {
    public let service: String

    public init(service: String) {
        self.service = service
    }

    public func key(for peer: String) -> SymmetricKey? {
        var query = baseQuery(peer)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return SymmetricKey(data: data)
    }

    public func setKey(_ key: SymmetricKey, for peer: String) {
        removeKey(for: peer)
        var item = baseQuery(peer)
        item[kSecValueData as String] = key.data
        #if !os(macOS)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #endif
        let status = SecItemAdd(item as CFDictionary, nil)
        assert(status == errSecSuccess, "Tether couldn't store a key in the Keychain (OSStatus \(status))")
    }

    public func removeKey(for peer: String) {
        SecItemDelete(baseQuery(peer) as CFDictionary)
    }

    private func baseQuery(_ peer: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: peer,
        ]
        #if os(iOS) || os(watchOS) || os(tvOS) || os(visionOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        // On macOS the data protection keychain needs a keychain-access-groups
        // entitlement; the login keychain works for any app, sandboxed or not.
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
