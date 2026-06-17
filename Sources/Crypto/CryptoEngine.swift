import Foundation
import CryptoKit

// MARK: - CryptoEngine

enum CryptoEngine {
    static func dh(privateKey: Data, publicKey: Data) -> Data? {
        guard let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey),
              let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey),
              let shared = try? priv.sharedSecretFromKeyAgreement(with: pub)
        else { return nil }
        return shared.withUnsafeBytes { Data($0) }
    }

    static func generateDH() -> (priv: Data, pub: Data) {
        let k = Curve25519.KeyAgreement.PrivateKey()
        return (k.rawRepresentation, k.publicKey.rawRepresentation)
    }

    static func hkdfDerive(ikm: Data, salt: Data, info: Data, length: Int = 32) -> Data {
        let key = SymmetricKey(data: ikm)
        let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: length)
        return derived.withUnsafeBytes { Data($0) }
    }

    static func encryptAEAD(key: Data, plaintext: Data, aad: Data = Data()) -> Data? {
        let nonce = ChaChaPoly.Nonce()
        guard let sealed = try? ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce, authenticating: aad)
        else { return nil }
        return sealed.combined
    }

    static func decryptAEAD(key: Data, data: Data, aad: Data = Data()) -> Data? {
        guard let box = try? ChaChaPoly.SealedBox(combined: data),
              let pt = try? ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
        else { return nil }
        return pt
    }

    static func hmacSHA256(key: Data, data: Data) -> Data {
        let h = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(h)
    }

    static func computeFingerprint(verifyKey: Data, dhPublic: Data) -> String {
        let hash = SHA256.hash(data: verifyKey + dhPublic)
        let hex = hash.map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: 32, by: 4).map { String(hex[hex.index(hex.startIndex, offsetBy: $0)..<hex.index(hex.startIndex, offsetBy: $0+4)]) }.joined(separator: " ")
    }
}

// MARK: - Identity

struct Identity {
    let signingKey: Curve25519.Signing.PrivateKey
    let verifyKey: Curve25519.Signing.PublicKey
    let dhPrivate: Data
    let dhPublic: Data

    static func generate() -> Identity {
        let sk = Curve25519.Signing.PrivateKey()
        let dh = Curve25519.KeyAgreement.PrivateKey()
        return Identity(signingKey: sk, verifyKey: sk.publicKey, dhPrivate: dh.rawRepresentation, dhPublic: dh.publicKey.rawRepresentation)
    }

    static func fromSaved(_ d: [String: String]) -> Identity? {
        guard let skH = d["signing_key"], let dhPH = d["dh_private"], let dhPuH = d["dh_public"],
              let skD = Data(hexString: skH), let dhPr = Data(hexString: dhPH), let dhPu = Data(hexString: dhPuH),
              let sk = try? Curve25519.Signing.PrivateKey(rawRepresentation: skD) else { return nil }
        return Identity(signingKey: sk, verifyKey: sk.publicKey, dhPrivate: dhPr, dhPublic: dhPu)
    }

    func export() -> [String: String] {
        ["signing_key": signingKey.rawRepresentation.hexString, "dh_private": dhPrivate.hexString, "dh_public": dhPublic.hexString]
    }

    func getFingerprint() -> String {
        CryptoEngine.computeFingerprint(verifyKey: verifyKey.rawRepresentation, dhPublic: dhPublic)
    }
}

// MARK: - Double Ratchet

class DoubleRatchet {
    static let headerSize = 40 // 32 pub + 4 prevChain + 4 msgNum
    static let maxSkip = 512

    var rootKey = Data()
    var sendChainKey = Data()
    var recvChainKey = Data()
    var sendMsgNum: UInt32 = 0
    var recvMsgNum: UInt32 = 0
    var prevChainLength: UInt32 = 0
    var dhPrivate = Data()
    var dhPublic = Data()
    var peerDhPublic = Data()
    var skippedKeys: [String: Data] = [:]

    func initSender(sharedSecret: Data, peerDH: Data) {
        peerDhPublic = peerDH
        let kp = CryptoEngine.generateDH()
        dhPrivate = kp.priv; dhPublic = kp.pub
        guard let dhOut = CryptoEngine.dh(privateKey: dhPrivate, publicKey: peerDhPublic) else { return }
        let derived = CryptoEngine.hkdfDerive(ikm: dhOut, salt: sharedSecret, info: Data("EpiphyteRatchetInit".utf8), length: 64)
        rootKey = derived.prefix(32)
        sendChainKey = derived.suffix(32)
        sendMsgNum = 0; recvMsgNum = 0; prevChainLength = 0
    }

    func initReceiver(sharedSecret: Data, keypair: (priv: Data, pub: Data)) {
        dhPrivate = keypair.priv; dhPublic = keypair.pub
        rootKey = sharedSecret
        sendMsgNum = 0; recvMsgNum = 0; prevChainLength = 0
    }

    func encrypt(_ plaintext: Data) -> Data {
        let (newChain, msgKey) = kdfChain(sendChainKey)
        sendChainKey = newChain
        var header = dhPublic
        header.append(withUnsafeBytes(of: prevChainLength) { Data($0) })
        header.append(withUnsafeBytes(of: sendMsgNum) { Data($0) })
        sendMsgNum += 1
        let ct = CryptoEngine.encryptAEAD(key: msgKey, plaintext: plaintext, aad: header) ?? Data()
        return header + ct
    }

    func decrypt(_ message: Data) -> Data? {
        guard message.count >= Self.headerSize else { return nil }
        let header = message.prefix(Self.headerSize)
        let ct = message.dropFirst(Self.headerSize)
        let peerPub = Data(header.prefix(32))
        let prevLen: UInt32 = header.advanced(by: 32).withUnsafeBytes { $0.load(as: UInt32.self) }
        let msgNum: UInt32 = header.advanced(by: 36).withUnsafeBytes { $0.load(as: UInt32.self) }

        let keyId = "\(peerPub.hexString):\(msgNum)"
        if let mk = skippedKeys.removeValue(forKey: keyId) {
            return CryptoEngine.decryptAEAD(key: mk, data: Data(ct), aad: Data(header))
        }
        if peerPub != peerDhPublic {
            skipMessages(until: prevLen)
            dhRatchet(newPeerPub: peerPub)
        }
        while recvMsgNum < msgNum {
            let (nc, mk) = kdfChain(recvChainKey)
            recvChainKey = nc
            skippedKeys["\(peerDhPublic.hexString):\(recvMsgNum)"] = mk
            recvMsgNum += 1
            pruneSkipped()
        }
        let (nc, msgKey) = kdfChain(recvChainKey)
        recvChainKey = nc
        recvMsgNum += 1
        return CryptoEngine.decryptAEAD(key: msgKey, data: Data(ct), aad: Data(header))
    }

    private func kdfChain(_ chainKey: Data) -> (chain: Data, msg: Data) {
        (CryptoEngine.hmacSHA256(key: chainKey, data: Data([0x01])),
         CryptoEngine.hmacSHA256(key: chainKey, data: Data([0x02])))
    }

    private func skipMessages(until: UInt32) {
        guard !recvChainKey.isEmpty else { return }
        let count = min(Int(until) - Int(recvMsgNum), Self.maxSkip)
        for _ in 0..<count {
            let (nc, mk) = kdfChain(recvChainKey)
            recvChainKey = nc
            skippedKeys["\(peerDhPublic.hexString):\(recvMsgNum)"] = mk
            recvMsgNum += 1
        }
        pruneSkipped()
    }

    private func dhRatchet(newPeerPub: Data) {
        prevChainLength = sendMsgNum
        sendMsgNum = 0; recvMsgNum = 0
        peerDhPublic = newPeerPub
        if let dhRecv = CryptoEngine.dh(privateKey: dhPrivate, publicKey: peerDhPublic) {
            let d = CryptoEngine.hkdfDerive(ikm: dhRecv, salt: rootKey, info: Data("EpiphyteRatchet".utf8), length: 64)
            rootKey = d.prefix(32); recvChainKey = Data(d.suffix(32))
        }
        let kp = CryptoEngine.generateDH()
        dhPrivate = kp.priv; dhPublic = kp.pub
        if let dhSend = CryptoEngine.dh(privateKey: dhPrivate, publicKey: peerDhPublic) {
            let d = CryptoEngine.hkdfDerive(ikm: dhSend, salt: rootKey, info: Data("EpiphyteRatchet".utf8), length: 64)
            rootKey = d.prefix(32); sendChainKey = Data(d.suffix(32))
        }
    }

    private func pruneSkipped() {
        while skippedKeys.count > Self.maxSkip {
            if let firstKey = skippedKeys.keys.first { skippedKeys.removeValue(forKey: firstKey) }
            else { break }
        }
    }

    func exportState() -> [String: Any] {
        ["root_key": rootKey.hexString, "send_chain_key": sendChainKey.hexString,
         "recv_chain_key": recvChainKey.hexString, "send_msg_num": sendMsgNum,
         "recv_msg_num": recvMsgNum, "prev_chain_length": prevChainLength,
         "dh_private": dhPrivate.hexString, "dh_public": dhPublic.hexString,
         "peer_dh_public": peerDhPublic.hexString, "skipped_keys": skippedKeys.mapValues { $0.hexString }]
    }

    func importState(_ s: [String: Any]) {
        rootKey = Data(hexString: s["root_key"] as? String ?? "") ?? Data()
        sendChainKey = Data(hexString: s["send_chain_key"] as? String ?? "") ?? Data()
        recvChainKey = Data(hexString: s["recv_chain_key"] as? String ?? "") ?? Data()
        sendMsgNum = s["send_msg_num"] as? UInt32 ?? 0
        recvMsgNum = s["recv_msg_num"] as? UInt32 ?? 0
        prevChainLength = s["prev_chain_length"] as? UInt32 ?? 0
        dhPrivate = Data(hexString: s["dh_private"] as? String ?? "") ?? Data()
        dhPublic = Data(hexString: s["dh_public"] as? String ?? "") ?? Data()
        peerDhPublic = Data(hexString: s["peer_dh_public"] as? String ?? "") ?? Data()
        if let sk = s["skipped_keys"] as? [String: String] {
            skippedKeys = sk.compactMapValues { Data(hexString: $0) }
        }
    }
}
