# Epiphyte iOS/macOS (Swift)

End-to-end encrypted messenger over Tor. Native SwiftUI app with embedded Tor — no external apps needed.

## Features

All features identical to Windows and Android versions:
- E2E encryption (X3DH + Double Ratchet)
- Embedded Tor with bridge support
- Disappearing messages
- Panic wipe
- Decoy mode
- Group chat (Sender Keys)
- File transfer
- Traffic padding
- Screenshot protection (iOS)

## Building

### Prerequisites
- Xcode 15+
- macOS 13+ (for development)
- Tor.framework (see below)

### Getting Tor.framework

For iOS, you need to embed Tor as a framework:

```bash
# Option 1: Use iCepa's pre-built Tor.framework
git clone https://github.com/nicklockwood/tor-ios-framework.git
# Copy Tor.framework to your Xcode project

# Option 2: Build from source (recommended for App Store)
git clone https://github.com/nicklockwood/Tor.framework.git
cd Tor.framework
./build.sh
```

Then in Xcode:
1. Drag `Tor.framework` into the project
2. Add to "Embed & Sign" in target settings
3. Also embed `obfs4proxy` binary for bridge support

### Build & Run

```bash
# Open in Xcode
open EpiphyteSwift/

# Or build from command line
xcodebuild -scheme Epiphyte -destination 'platform=iOS Simulator,name=iPhone 15'
```

### macOS (no framework needed)

On macOS, the app can use a system-installed tor binary:
```bash
brew install tor
swift run
```

## Protocol Compatibility

100% wire-compatible with Windows (Python) and Android (Kotlin):
- Frame: `length(4 BE) + CRC32(4 BE) + data`
- Protocol: `version(1) + type(1) + msg_id(8 LE) + timestamp(8 LE) + payload_len(4 LE) + payload + sig_len(2 LE) + sig`
- Crypto: X25519 DH + Ed25519 signing + ChaCha20-Poly1305 AEAD + HKDF-SHA256

## App Store Submission

1. Embed Tor.framework + obfs4proxy
2. Add Network Extension entitlement (for SOCKS proxy)
3. Set NSAllowsArbitraryLoads for localhost in Info.plist
4. Privacy manifest: declare network usage
5. Archive → Upload to App Store Connect

Apps with embedded Tor have been approved (Onion Browser, etc.).
