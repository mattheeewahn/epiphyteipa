import Foundation
import CryptoKit

class Session {
    let identity: Identity
    let peerOnion: String
    var peerVerifyKey: Curve25519.Signing.PublicKey?
    var peerDhPublic = Data()
    var peerFingerprint = ""
    var ratchet: DoubleRatchet?
    var established = false
    private var msgCounter = 0
    private var ephPrivate = Data()
    private var ephPublic = Data()

    init(identity: Identity, peerOnion: String) {
        self.identity = identity
        self.peerOnion = peerOnion
    }

    func createKeyExchangeInit() -> Data {
        let kp = CryptoEngine.generateDH()
        ephPrivate = kp.priv; ephPublic = kp.pub
        let payload: [String: String] = [
            "verify_key": identity.verifyKey.rawRepresentation.hexString,
            "dh_public": identity.dhPublic.hexString,
            "ephemeral_public": ephPublic.hexString,
            "protocol_version": "1"
        ]
        guard let payloadData = try? JSONSerialization.data(withJSONObject: payload),
              let sig = try? identity.signingKey.signature(for: payloadData)
        else { return Data() }

        let msg = ProtocolMessage(msgType: .keyExchange, payload: payloadData, timestamp: Date(), msgId: nextId(), signature: Data(sig))
        return msg.serialize()
    }

    func handleKeyExchangeInit(_ data: Data) -> Data? {
        guard let msg = ProtocolMessage.deserialize(data), msg.msgType == .keyExchange else { return nil }
        guard let payload = try? JSONSerialization.jsonObject(with: msg.payload) as? [String: String],
              let vkHex = payload["verify_key"], let dhHex = payload["dh_public"], let ephHex = payload["ephemeral_public"],
              let vkData = Data(hexString: vkHex), let peerDH = Data(hexString: dhHex), let peerEph = Data(hexString: ephHex),
              let vk = try? Curve25519.Signing.PublicKey(rawRepresentation: vkData),
              vk.isValidSignature(msg.signature, for: msg.payload)
        else { return nil }

        peerVerifyKey = vk
        peerDhPublic = peerDH
        peerFingerprint = CryptoEngine.computeFingerprint(verifyKey: vkData, dhPublic: peerDH)

        let kp = CryptoEngine.generateDH()
        ephPrivate = kp.priv; ephPublic = kp.pub

        guard let dh1 = CryptoEngine.dh(privateKey: identity.dhPrivate, publicKey: peerEph),
              let dh2 = CryptoEngine.dh(privateKey: ephPrivate, publicKey: peerDH),
              let dh3 = CryptoEngine.dh(privateKey: ephPrivate, publicKey: peerEph)
        else { return nil }

        let shared = CryptoEngine.hkdfDerive(ikm: dh1 + dh2 + dh3, salt: Data("Epiphyte-X3DH".utf8), info: Data("session-key".utf8))
        let ratchetKP = CryptoEngine.generateDH()
        ratchet = DoubleRatchet()
        ratchet?.initReceiver(sharedSecret: shared, keypair: ratchetKP)

        let replyPayload: [String: String] = [
            "verify_key": identity.verifyKey.rawRepresentation.hexString,
            "dh_public": identity.dhPublic.hexString,
            "ephemeral_public": ephPublic.hexString,
            "ratchet_public": ratchetKP.pub.hexString,
            "protocol_version": "1"
        ]
        guard let replyData = try? JSONSerialization.data(withJSONObject: replyPayload),
              let sig = try? identity.signingKey.signature(for: replyData)
        else { return nil }

        established = true
        let reply = ProtocolMessage(msgType: .keyExchangeReply, payload: replyData, timestamp: Date(), msgId: nextId(), signature: Data(sig))
        return reply.serialize()
    }

    func handleKeyExchangeReply(_ data: Data) -> Bool {
        guard let msg = ProtocolMessage.deserialize(data), msg.msgType == .keyExchangeReply else { return false }
        guard let payload = try? JSONSerialization.jsonObject(with: msg.payload) as? [String: String],
              let vkHex = payload["verify_key"], let dhHex = payload["dh_public"],
              let ephHex = payload["ephemeral_public"], let ratchetHex = payload["ratchet_public"],
              let vkData = Data(hexString: vkHex), let peerDH = Data(hexString: dhHex),
              let peerEph = Data(hexString: ephHex), let peerRatchet = Data(hexString: ratchetHex),
              let vk = try? Curve25519.Signing.PublicKey(rawRepresentation: vkData),
              vk.isValidSignature(msg.signature, for: msg.payload)
        else { return false }

        peerVerifyKey = vk
        peerDhPublic = peerDH
        peerFingerprint = CryptoEngine.computeFingerprint(verifyKey: vkData, dhPublic: peerDH)

        guard let dh1 = CryptoEngine.dh(privateKey: ephPrivate, publicKey: peerDH),
              let dh2 = CryptoEngine.dh(privateKey: identity.dhPrivate, publicKey: peerEph),
              let dh3 = CryptoEngine.dh(privateKey: ephPrivate, publicKey: peerEph)
        else { return false }

        let shared = CryptoEngine.hkdfDerive(ikm: dh1 + dh2 + dh3, salt: Data("Epiphyte-X3DH".utf8), info: Data("session-key".utf8))
        ratchet = DoubleRatchet()
        ratchet?.initSender(sharedSecret: shared, peerDH: peerRatchet)
        established = true
        return true
    }

    func encryptMessage(_ text: String) -> Data? {
        guard established, let r = ratchet else { return nil }
        let ct = r.encrypt(Data(text.utf8))
        let msg = ProtocolMessage(msgType: .text, payload: ct, timestamp: Date(), msgId: nextId())
        return msg.serialize()
    }

    func decryptMessage(_ data: Data) -> String? {
        guard established, let r = ratchet, let msg = ProtocolMessage.deserialize(data), msg.msgType == .text else { return nil }
        guard let pt = r.decrypt(msg.payload) else { return nil }
        return String(data: pt, encoding: .utf8)
    }

    func createAck(msgId: Int) -> Data {
        var payload = Data()
        withUnsafeBytes(of: Int64(msgId)) { payload.append(contentsOf: $0) }
        return ProtocolMessage(msgType: .deliveryReceipt, payload: payload, timestamp: Date(), msgId: nextId()).serialize()
    }

    func createSessionReset() -> Data {
        ProtocolMessage(msgType: .sessionReset, payload: Data(), timestamp: Date(), msgId: nextId()).serialize()
    }

    func exportState() -> [String: Any] {
        var s: [String: Any] = ["peer_onion": peerOnion, "established": established, "msg_counter": msgCounter, "peer_fingerprint": peerFingerprint]
        if let vk = peerVerifyKey { s["peer_verify_key"] = vk.rawRepresentation.hexString }
        if !peerDhPublic.isEmpty { s["peer_dh_public"] = peerDhPublic.hexString }
        if let r = ratchet { s["ratchet"] = r.exportState() }
        return s
    }

    func importState(_ s: [String: Any]) -> Bool {
        established = s["established"] as? Bool ?? false
        msgCounter = s["msg_counter"] as? Int ?? 0
        peerFingerprint = s["peer_fingerprint"] as? String ?? ""
        if let vkH = s["peer_verify_key"] as? String, let vkD = Data(hexString: vkH) {
            peerVerifyKey = try? Curve25519.Signing.PublicKey(rawRepresentation: vkD)
        }
        if let dh = s["peer_dh_public"] as? String { peerDhPublic = Data(hexString: dh) ?? Data() }
        if let rs = s["ratchet"] as? [String: Any] { ratchet = DoubleRatchet(); ratchet?.importState(rs) }
        return true
    }

    private func nextId() -> Int { msgCounter += 1; return msgCounter }
}
