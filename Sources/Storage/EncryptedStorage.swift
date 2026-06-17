import Foundation
import CryptoKit

class EncryptedStorage {
    private let dataDir: URL
    private let storeDir: URL
    private var key: SymmetricKey?
    private(set) var isOpen = false

    init(dataDir: URL) {
        self.dataDir = dataDir
        self.storeDir = dataDir.appendingPathComponent("store")
        try? FileManager.default.createDirectory(at: storeDir, withIntermediateDirectories: true)
    }

    func open(passphrase: String) -> Bool {
        let saltFile = storeDir.appendingPathComponent("salt")
        let verifyFile = storeDir.appendingPathComponent("verify")

        let salt: Data
        if let existing = try? Data(contentsOf: saltFile) {
            salt = existing
        } else {
            salt = Data.random(count: 16)
            try? salt.write(to: saltFile)
        }

        key = deriveKey(passphrase: passphrase, salt: salt)

        if FileManager.default.fileExists(atPath: verifyFile.path) {
            guard let encrypted = try? Data(contentsOf: verifyFile),
                  let decrypted = decrypt(encrypted),
                  decrypted == Data("EPIPHYTE_OK".utf8) else {
                key = nil
                return false
            }
        } else {
            guard let encrypted = encrypt(Data("EPIPHYTE_OK".utf8)) else { key = nil; return false }
            try? encrypted.write(to: verifyFile)
        }
        isOpen = true
        return true
    }

    func reset() {
        try? FileManager.default.removeItem(at: storeDir)
        try? FileManager.default.createDirectory(at: storeDir, withIntermediateDirectories: true)
    }

    func close() { key = nil; isOpen = false }

    // MARK: - Identity
    func saveIdentity(_ data: [String: String]) { put(key: "identity", value: data) }
    func loadIdentity() -> [String: String]? { get(key: "identity") }

    // MARK: - Contacts
    func saveContact(_ c: Contact) {
        var all = loadContacts()
        if let i = all.firstIndex(where: { $0.onionAddress == c.onionAddress }) { all[i] = c } else { all.append(c) }
        put(key: "contacts", value: all.map { $0.toDict() })
    }
    func loadContacts() -> [Contact] {
        guard let arr: [[String: Any]] = get(key: "contacts") else { return [] }
        return arr.compactMap { Contact.fromDict($0) }
    }
    func removeContact(_ addr: String) {
        var all = loadContacts()
        all.removeAll { $0.onionAddress == addr }
        put(key: "contacts", value: all.map { $0.toDict() })
    }

    // MARK: - Messages
    func saveMessage(peer: String, message: ChatMessage) {
        let k = "messages_\(peer.prefix(16))"
        var msgs: [[String: Any]] = get(key: k) ?? []
        msgs.append(message.toDict())
        if msgs.count > 5000 { msgs = Array(msgs.suffix(5000)) }
        put(key: k, value: msgs)
    }
    func loadMessages(peer: String) -> [ChatMessage] {
        let k = "messages_\(peer.prefix(16))"
        guard let arr: [[String: Any]] = get(key: k) else { return [] }
        return arr.suffix(200).compactMap { ChatMessage.fromDict($0) }
    }
    func deleteMessages(peer: String) { put(key: "messages_\(peer.prefix(16))", value: [[String: Any]]()) }

    // MARK: - Sessions
    func saveSession(peer: String, state: [String: Any]) { put(key: "session_\(peer.prefix(16))", value: state) }
    func loadSession(peer: String) -> [String: Any]? { get(key: "session_\(peer.prefix(16))") }
    func deleteSession(peer: String) {
        let file = storeDir.appendingPathComponent(safeFilename("session_\(peer.prefix(16))") + ".enc")
        try? FileManager.default.removeItem(at: file)
    }

    // MARK: - Internal
    private func deriveKey(passphrase: String, salt: Data) -> SymmetricKey {
        // Use PBKDF2 as scrypt isn't in CryptoKit (or use CommonCrypto)
        let passData = Data(passphrase.utf8)
        let derived = CryptoEngine.hkdfDerive(ikm: passData + salt, salt: salt, info: Data("epiphyte-storage".utf8), length: 32)
        return SymmetricKey(data: derived)
    }

    private func encrypt(_ data: Data) -> Data? {
        guard let k = key else { return nil }
        guard let sealed = try? ChaChaPoly.seal(data, using: k) else { return nil }
        return sealed.combined
    }

    private func decrypt(_ data: Data) -> Data? {
        guard let k = key else { return nil }
        guard let box = try? ChaChaPoly.SealedBox(combined: data),
              let pt = try? ChaChaPoly.open(box, using: k) else { return nil }
        return pt
    }

    private func put<T: Encodable>(key k: String, value: T) {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: value),
              let encrypted = encrypt(jsonData) else { return }
        let file = storeDir.appendingPathComponent(safeFilename(k) + ".enc")
        try? encrypted.write(to: file, options: .atomic)
    }

    private func put(key k: String, value: Any) {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: value),
              let encrypted = encrypt(jsonData) else { return }
        let file = storeDir.appendingPathComponent(safeFilename(k) + ".enc")
        try? encrypted.write(to: file, options: .atomic)
    }

    private func get<T>(key k: String) -> T? {
        let file = storeDir.appendingPathComponent(safeFilename(k) + ".enc")
        guard let encrypted = try? Data(contentsOf: file), let decrypted = decrypt(encrypted) else { return nil }
        return try? JSONSerialization.jsonObject(with: decrypted) as? T
    }

    private func safeFilename(_ key: String) -> String {
        SHA256.hash(data: Data(key.utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}
