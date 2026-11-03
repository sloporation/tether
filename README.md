# tether

Pairs your iOS app with your macOS app over the local network, then gives both sides an encrypted
connection to talk over. No server, no cloud: the Mac advertises itself with Bonjour, the iPhone finds it,
they pair once with a six-digit code, and after that they can connect whenever they're on the same network.

What the two apps *say* to each other is up to them: tether hands each side a `TetherSession` that sends
and receives any `Codable` messages.

## How it works

- **Discovery.** The host (Mac) advertises a Bonjour service with its id in the TXT record. The client
  (iPhone) browses for it.
- **Pairing.** Each side sends its half of a Curve25519 key agreement; both derive the same key and the same
  six-digit code with HKDF. The client commits to (sends a hash of) its half before seeing the host's, so
  someone in the middle can't search for halves that give matching codes. The person checks the codes match
  and allows the device on the host.
- **Connecting.** TLS 1.2 with a pre-shared key per paired device (`TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256`,
  so a key found later can't open traffic recorded before). The host greets with a random challenge; the
  client proves which device it is with an HMAC of it. Keys are stored in the Keychain.
- **Messages.** A 4-byte big-endian length, then that much JSON. For something large, such as a file, send a message
  that says how many bytes follow, then `send(bytes:)`; the other side reads them with `receiveFile(size:to:)`.

## Using it

Both apps list the service type in `Info.plist`:

```xml
<key>NSBonjourServices</key>
<array><string>_myapp._tcp</string></array>
<key>NSLocalNetworkUsageDescription</key>
<string>MyApp finds MyApp on your Mac to sync with it.</string>
```

A sandboxed Mac app also needs `com.apple.security.network.server` and `com.apple.security.network.client`.

```swift
import Tether

let configuration = TetherConfiguration(serviceType: "_myapp._tcp", label: "myapp")

// Mac
let host = TetherHost(configuration: configuration, name: Host.current().localizedName ?? "Mac")
host.onSession = { session in
    let request = try? await session.receive(MyRequest.self)
    try? await session.send(MyReply(...))
}
await host.start()
// Show host.pairingRequest (its code) and call host.allow(id) / host.refuse(id).

// iPhone
let client = TetherClient(configuration: configuration, name: "iPhone")
client.startBrowsing()
try await client.pair(with: client.discovered[0]) { code in /* show the code */ }
let session = try await client.connect(to: client.reachablePairedHosts[0])
try await session.send(MyRequest(...))
let reply = try await session.receive(MyReply.self)
```

## Tests

`swift test` runs the pairing crypto and a full pair → connect → message round trip over loopback.
