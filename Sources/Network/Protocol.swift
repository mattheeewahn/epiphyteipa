import Foundation

enum MsgType: UInt8 {
    case hello = 1, keyExchange = 2, keyExchangeReply = 3
    case text = 10, fileMeta = 11, fileChunk = 12
    case ack = 20, deliveryReceipt = 21, readReceipt = 22
    case ping = 30, pong = 31
    case sessionReset = 40
}

struct ProtocolMessage {
    let msgType: MsgType
    let payload: Data
    let timestamp: Date
    let msgId: Int
    var signature: Data = Data()

    func serialize() -> Data {
        var buf = Data()
        buf.append(1) // version
        buf.append(msgType.rawValue)
        withUnsafeBytes(of: Int64(msgId)) { buf.append(contentsOf: $0) }
        withUnsafeBytes(of: timestamp.timeIntervalSince1970) { buf.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt32(payload.count)) { buf.append(contentsOf: $0) }
        buf.append(payload)
        withUnsafeBytes(of: UInt16(signature.count)) { buf.append(contentsOf: $0) }
        buf.append(signature)
        return buf
    }

    static func deserialize(_ data: Data) -> ProtocolMessage? {
        guard data.count >= 22 else { return nil }
        let version = data[0]
        guard version == 1 else { return deserializeLegacy(data) }
        guard let type = MsgType(rawValue: data[1]) else { return nil }
        let msgId: Int64 = data.advanced(by: 2).withUnsafeBytes { $0.load(as: Int64.self) }
        let ts: Double = data.advanced(by: 10).withUnsafeBytes { $0.load(as: Double.self) }
        let payloadLen: UInt32 = data.advanced(by: 18).withUnsafeBytes { $0.load(as: UInt32.self) }
        let offset = 22
        guard data.count >= offset + Int(payloadLen) + 2 else { return nil }
        let payload = data[offset..<offset+Int(payloadLen)]
        let sigLen: UInt16 = data.advanced(by: offset + Int(payloadLen)).withUnsafeBytes { $0.load(as: UInt16.self) }
        let sigOffset = offset + Int(payloadLen) + 2
        let sig = sigLen > 0 ? data[sigOffset..<sigOffset+Int(sigLen)] : Data()
        return ProtocolMessage(msgType: type, payload: Data(payload), timestamp: Date(timeIntervalSince1970: ts), msgId: Int(msgId), signature: Data(sig))
    }

    private static func deserializeLegacy(_ data: Data) -> ProtocolMessage? {
        guard data.count >= 21, let type = MsgType(rawValue: data[0]) else { return nil }
        let msgId: Int64 = data.advanced(by: 1).withUnsafeBytes { $0.load(as: Int64.self) }
        let ts: Float = data.advanced(by: 9).withUnsafeBytes { $0.load(as: Float.self) }
        let payloadLen: UInt32 = data.advanced(by: 13).withUnsafeBytes { $0.load(as: UInt32.self) }
        let offset = 17
        guard data.count >= offset + Int(payloadLen) + 2 else { return nil }
        let payload = data[offset..<offset+Int(payloadLen)]
        let sigLen: UInt16 = data.advanced(by: offset + Int(payloadLen)).withUnsafeBytes { $0.load(as: UInt16.self) }
        let sigOffset = offset + Int(payloadLen) + 2
        let sig = sigLen > 0 && data.count >= sigOffset + Int(sigLen) ? data[sigOffset..<sigOffset+Int(sigLen)] : Data()
        return ProtocolMessage(msgType: type, payload: Data(payload), timestamp: Date(timeIntervalSince1970: Double(ts)), msgId: Int(msgId), signature: Data(sig))
    }
}
