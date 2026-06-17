import Foundation
import CryptoKit

// MARK: - Panic Wipe

class PanicWipe {
    private let dataDir: URL
    private var panicFile: URL { dataDir.appendingPathComponent(".panic") }

    init(dataDir: URL) { self.dataDir = dataDir }

    func setPanicPassphrase(_ passphrase: String) {
        var salt = Data.random(count: 16)
        let hash = CryptoEngine.hkdfDerive(ikm: Data(passphrase.utf8), salt: salt, info: Data("panic".utf8))
        try? (salt + hash).write(to: panicFile)
    }

    func checkPanic(passphrase: String) -> Bool {
        guard let data = try? Data(contentsOf: panicFile), data.count >= 48 else { return false }
        let salt = data.prefix(16)
        let stored = data.suffix(32)
        let hash = CryptoEngine.hkdfDerive(ikm: Data(passphrase.utf8), salt: salt, info: Data("panic".utf8))
        return hash == stored
    }

    func executeWipe() {
        let dirs = ["store", "tor_data", "hidden_service", "transfers", "backups"]
        for d in dirs {
            let path = dataDir.appendingPathComponent(d)
            try? FileManager.default.removeItem(at: path)
        }
        for f in (try? FileManager.default.contentsOfDirectory(at: dataDir, includingPropertiesForKeys: nil)) ?? [] {
            try? FileManager.default.removeItem(at: f)
        }
    }
}

// MARK: - Decoy Mode

class DecoyMode {
    private let dataDir: URL
    private var decoyFile: URL { dataDir.appendingPathComponent(".decoy") }

    init(dataDir: URL) { self.dataDir = dataDir }

    func setupDecoy(_ passphrase: String) {
        let salt = Data.random(count: 16)
        let hash = CryptoEngine.hkdfDerive(ikm: Data(passphrase.utf8), salt: salt, info: Data("decoy".utf8))
        try? (salt + hash).write(to: decoyFile)
    }

    func isDecoyPassphrase(_ passphrase: String) -> Bool {
        guard let data = try? Data(contentsOf: decoyFile), data.count >= 48 else { return false }
        let salt = data.prefix(16)
        let stored = data.suffix(32)
        let hash = CryptoEngine.hkdfDerive(ikm: Data(passphrase.utf8), salt: salt, info: Data("decoy".utf8))
        return hash == stored
    }
}

// MARK: - Disappearing Messages

class DisappearingManager {
    private var configs: [String: (enabled: Bool, seconds: Int)] = [:]
    private var timers: [String: Date] = [:] // msgId -> destroyAt

    func setConfig(peer: String, enabled: Bool, seconds: Int) {
        configs[peer] = (enabled, seconds)
    }

    func getConfig(peer: String) -> (enabled: Bool, seconds: Int) {
        configs[peer] ?? (false, 300)
    }

    func schedule(msgId: String, peer: String) {
        let cfg = getConfig(peer: peer)
        guard cfg.enabled else { return }
        timers[msgId] = Date().addingTimeInterval(Double(cfg.seconds))
    }

    func getExpired() -> [String] {
        let now = Date()
        let expired = timers.filter { $0.value <= now }.map { $0.key }
        for id in expired { timers.removeValue(forKey: id) }
        return expired
    }

    func exportState() -> [String: Any] {
        ["configs": configs.mapValues { ["enabled": $0.enabled, "seconds": $0.seconds] },
         "timers": timers.mapValues { $0.timeIntervalSince1970 }]
    }

    func importState(_ s: [String: Any]) {
        if let c = s["configs"] as? [String: [String: Any]] {
            for (k, v) in c { configs[k] = (v["enabled"] as? Bool ?? false, v["seconds"] as? Int ?? 300) }
        }
        if let t = s["timers"] as? [String: Double] {
            timers = t.mapValues { Date(timeIntervalSince1970: $0) }
        }
    }
}

// MARK: - Vanity Generator

class VanityGenerator {
    private var running = false
    var attempts = 0

    func start(prefix: String, completion: @escaping (String?, Curve25519.Signing.PrivateKey?) -> Void) {
        running = true; attempts = 0
        let pfx = prefix.lowercased()
        DispatchQueue.global(qos: .background).async {
            while self.running {
                let key = Curve25519.Signing.PrivateKey()
                let addr = Self.onionAddress(from: key)
                self.attempts += 1
                if addr.hasPrefix(pfx) {
                    self.running = false
                    DispatchQueue.main.async { completion(addr, key) }
                    return
                }
            }
            DispatchQueue.main.async { completion(nil, nil) }
        }
    }

    func stop() { running = false }

    static func onionAddress(from key: Curve25519.Signing.PrivateKey) -> String {
        let pub = key.publicKey.rawRepresentation
        let version = Data([0x03])
        let checksumInput = Data(".onion checksum".utf8) + pub + version
        let checksum = Data(SHA256.hash(data: checksumInput)).prefix(2)
        let addrBytes = pub + checksum + version
        return addrBytes.base32Encoded().lowercased()
    }

    static func writeKeyFiles(key: Curve25519.Signing.PrivateKey, dir: URL) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let pub = key.publicKey.rawRepresentation
        let addr = onionAddress(from: key) + ".onion\n"
        let pubHeader = Data("== ed25519v1-public: type0 ==\0\0\0".utf8)
        let secHeader = Data("== ed25519v1-secret: type0 ==\0\0\0".utf8)
        try? (pubHeader + pub).write(to: dir.appendingPathComponent("hs_ed25519_public_key"))
        try? (secHeader + key.rawRepresentation).write(to: dir.appendingPathComponent("hs_ed25519_secret_key"))
        try? addr.write(to: dir.appendingPathComponent("hostname"), atomically: true, encoding: .utf8)
    }
}

// MARK: - File Transfer Manager

class FileTransferManager {
    private let transfersDir: URL
    static let chunkSize = 64 * 1024

    init(dataDir: URL) {
        transfersDir = dataDir.appendingPathComponent("transfers")
        try? FileManager.default.createDirectory(at: transfersDir, withIntermediateDirectories: true)
    }

    func prepareSend(url: URL, burn: Bool) -> FileMetadata? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard data.count > 0, data.count <= 100 * 1024 * 1024 else { return nil }
        let hash = SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        let chunks = (data.count + Self.chunkSize - 1) / Self.chunkSize
        let fid = SHA256.hash(data: Data("\(url.lastPathComponent)\(data.count)\(Date().timeIntervalSince1970)".utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
        return FileMetadata(fileId: fid, filename: url.lastPathComponent, fileSize: data.count, chunkCount: chunks, sha256Hash: hash, burnAfterRead: burn)
    }

    func getChunk(url: URL, fileId: String, index: Int, key: Data) -> Data? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let start = index * Self.chunkSize
        let end = min(start + Self.chunkSize, data.count)
        let chunk = data[start..<end]
        var aad = Data(fileId.padding(toLength: 16, withPad: "\0", startingAt: 0).utf8)
        withUnsafeBytes(of: UInt32(index)) { aad.append(contentsOf: $0) }
        return CryptoEngine.encryptAEAD(key: key, plaintext: Data(chunk), aad: aad)
    }

    private var receiving: [String: Data] = [:]
    private var receiveMeta: [String: FileMetadata] = [:]

    func startReceive(metadata: FileMetadata) {
        receiveMeta[metadata.fileId] = metadata
        receiving[metadata.fileId] = Data(count: metadata.fileSize)
    }

    func receiveChunk(fileId: String, index: Int, data: Data, key: Data) -> Bool {
        guard let meta = receiveMeta[fileId] else { return false }
        var aad = Data(fileId.padding(toLength: 16, withPad: "\0", startingAt: 0).utf8)
        withUnsafeBytes(of: UInt32(index)) { aad.append(contentsOf: $0) }
        guard let decrypted = CryptoEngine.decryptAEAD(key: key, data: data, aad: aad) else { return false }
        let start = index * Self.chunkSize
        receiving[fileId]?.replaceSubrange(start..<start+decrypted.count, with: decrypted)
        if index + 1 >= meta.chunkCount {
            // Save file
            let dest = transfersDir.appendingPathComponent(meta.filename)
            try? receiving[fileId]?.write(to: dest)
            receiving.removeValue(forKey: fileId)
            receiveMeta.removeValue(forKey: fileId)
            return true
        }
        return false
    }
}

// MARK: - Group Manager

class GroupManager {
    var groups: [String: GroupInfo] = [:]
    private var senderKeys: [String: Data] = [:] // groupId -> our chain key
    private var peerKeys: [String: [String: Data]] = [:] // groupId -> {onion -> key}

    func createGroup(name: String, ourOnion: String) -> GroupInfo {
        let gid = SHA256.hash(data: Data("\(name)\(ourOnion)\(Date().timeIntervalSince1970)".utf8)).prefix(12).map { String(format: "%02x", $0) }.joined()
        let key = Data.random(count: 32)
        senderKeys[gid] = key
        let g = GroupInfo(groupId: gid, name: name, members: [GroupMember(onionAddress: ourOnion, displayName: "You", role: "admin")], createdAt: Date(), creator: ourOnion)
        groups[gid] = g
        peerKeys[gid] = [:]
        return g
    }

    func addMember(groupId: String, member: String, name: String, ourOnion: String) -> [String: Any]? {
        guard var g = groups[groupId], g.creator == ourOnion else { return nil }
        g.members.append(GroupMember(onionAddress: member, displayName: name))
        groups[groupId] = g
        return ["type": "group_invite", "group_id": groupId, "name": g.name, "creator": g.creator,
                "members": g.members.map { ["onion": $0.onionAddress, "name": $0.displayName, "role": $0.role] },
                "sender_key": senderKeys[groupId]?.hexString ?? ""]
    }

    func handleInvite(_ obj: [String: Any], ourOnion: String) -> String? {
        guard let gid = obj["group_id"] as? String, let name = obj["name"] as? String else { return nil }
        let key = Data.random(count: 32)
        senderKeys[gid] = key
        let members = (obj["members"] as? [[String: String]])?.map { GroupMember(onionAddress: $0["onion"] ?? "", displayName: $0["name"] ?? "", role: $0["role"] ?? "member") } ?? []
        groups[gid] = GroupInfo(groupId: gid, name: name, members: members, creator: obj["creator"] as? String ?? "")
        peerKeys[gid] = [:]
        if let sk = obj["sender_key"] as? String, let skData = Data(hexString: sk) {
            peerKeys[gid]?[obj["creator"] as? String ?? ""] = skData
        }
        return gid
    }

    func updatePeerKey(groupId: String, peer: String, keyHex: String, iteration: Int) {
        if peerKeys[groupId] == nil { peerKeys[groupId] = [:] }
        peerKeys[groupId]?[peer] = Data(hexString: keyHex)
    }

    func encrypt(groupId: String, text: String, ourOnion: String) -> Data? {
        guard var key = senderKeys[groupId] else { return nil }
        let msgKey = CryptoEngine.hmacSHA256(key: key, data: Data([0x02]))
        senderKeys[groupId] = CryptoEngine.hmacSHA256(key: key, data: Data([0x01]))
        let header = try? JSONSerialization.data(withJSONObject: ["sender": ourOnion, "group_id": groupId])
        guard let h = header, let ct = CryptoEngine.encryptAEAD(key: msgKey, plaintext: Data(text.utf8), aad: h) else { return nil }
        var result = Data()
        withUnsafeBytes(of: UInt32(h.count)) { result.append(contentsOf: $0) }
        result.append(h)
        result.append(ct)
        return result
    }

    func decryptMessage(groupId: String, data: Data) -> (sender: String, text: String)? {
        guard data.count > 4 else { return nil }
        let hLen: UInt32 = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        guard data.count > 4 + Int(hLen) else { return nil }
        let header = data[4..<4+Int(hLen)]
        let ct = data.dropFirst(4 + Int(hLen))
        guard let obj = try? JSONSerialization.jsonObject(with: header) as? [String: String],
              let sender = obj["sender"], var key = peerKeys[groupId]?[sender] else { return nil }
        let msgKey = CryptoEngine.hmacSHA256(key: key, data: Data([0x02]))
        peerKeys[groupId]?[sender] = CryptoEngine.hmacSHA256(key: key, data: Data([0x01]))
        guard let pt = CryptoEngine.decryptAEAD(key: msgKey, data: Data(ct), aad: Data(header)) else { return nil }
        return (sender, String(data: pt, encoding: .utf8) ?? "")
    }

    func exportState() -> [String: Any] {
        ["groups": groups.mapValues { ["name": $0.name, "creator": $0.creator, "members": $0.members.map { ["onion": $0.onionAddress, "name": $0.displayName, "role": $0.role] }] },
         "sender_keys": senderKeys.mapValues { $0.hexString },
         "peer_keys": peerKeys.mapValues { $0.mapValues { $0.hexString } }]
    }

    func importState(_ s: [String: Any]) {
        if let gs = s["groups"] as? [String: [String: Any]] {
            for (gid, gd) in gs {
                let members = (gd["members"] as? [[String: String]])?.map { GroupMember(onionAddress: $0["onion"] ?? "", displayName: $0["name"] ?? "", role: $0["role"] ?? "member") } ?? []
                groups[gid] = GroupInfo(groupId: gid, name: gd["name"] as? String ?? "", members: members, creator: gd["creator"] as? String ?? "")
            }
        }
        if let sk = s["sender_keys"] as? [String: String] { senderKeys = sk.compactMapValues { Data(hexString: $0) } }
        if let pk = s["peer_keys"] as? [String: [String: String]] { peerKeys = pk.mapValues { $0.compactMapValues { Data(hexString: $0) } } }
    }
}
