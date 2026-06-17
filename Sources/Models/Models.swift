import Foundation

struct Contact: Identifiable {
    var id: String { onionAddress }
    var onionAddress: String
    var displayName: String
    var fingerprint: String = ""
    var addedAt: Date = Date()
    var lastSeen: Date = Date()
    var verified: Bool = false
    var blocked: Bool = false
    var status: ContactStatus = .offline

    func toDict() -> [String: Any] {
        ["onion_address": onionAddress, "display_name": displayName, "fingerprint": fingerprint,
         "added_at": addedAt.timeIntervalSince1970, "last_seen": lastSeen.timeIntervalSince1970,
         "verified": verified, "blocked": blocked]
    }
    static func fromDict(_ d: [String: Any]) -> Contact? {
        guard let addr = d["onion_address"] as? String else { return nil }
        return Contact(onionAddress: addr, displayName: d["display_name"] as? String ?? "",
                       fingerprint: d["fingerprint"] as? String ?? "",
                       addedAt: Date(timeIntervalSince1970: d["added_at"] as? Double ?? 0),
                       lastSeen: Date(timeIntervalSince1970: d["last_seen"] as? Double ?? 0),
                       verified: d["verified"] as? Bool ?? false, blocked: d["blocked"] as? Bool ?? false)
    }
}

struct ChatMessage: Identifiable {
    let id: String
    let sender: String
    let text: String
    let timestamp: Date
    let isOurs: Bool
    var isSystem: Bool = false
    var delivered: Bool = true

    func toDict() -> [String: Any] {
        ["id": id, "sender": sender, "text": text, "timestamp": timestamp.timeIntervalSince1970,
         "is_ours": isOurs, "is_system": isSystem, "delivered": delivered]
    }
    static func fromDict(_ d: [String: Any]) -> ChatMessage? {
        guard let id = d["id"] as? String, let sender = d["sender"] as? String, let text = d["text"] as? String else { return nil }
        return ChatMessage(id: id, sender: sender, text: text,
                           timestamp: Date(timeIntervalSince1970: d["timestamp"] as? Double ?? 0),
                           isOurs: d["is_ours"] as? Bool ?? false, isSystem: d["is_system"] as? Bool ?? false)
    }
}

struct GroupInfo: Identifiable {
    var id: String { groupId }
    let groupId: String
    var name: String
    var members: [GroupMember] = []
    var createdAt: Date = Date()
    var creator: String = ""
}

struct GroupMember {
    var onionAddress: String
    var displayName: String
    var role: String = "member"
}

struct FileMetadata {
    let fileId: String
    let filename: String
    let fileSize: Int
    let chunkCount: Int
    let sha256Hash: String
    var burnAfterRead: Bool = false

    func serialize() -> Data {
        let d: [String: Any] = ["file_id": fileId, "filename": filename, "file_size": fileSize,
                                "chunk_count": chunkCount, "sha256_hash": sha256Hash, "burn_after_read": burnAfterRead]
        return (try? JSONSerialization.data(withJSONObject: d)) ?? Data()
    }
    static func deserialize(_ data: Data) -> FileMetadata? {
        guard let d = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let fid = d["file_id"] as? String, let fn = d["filename"] as? String,
              let fs = d["file_size"] as? Int, let cc = d["chunk_count"] as? Int, let hash = d["sha256_hash"] as? String
        else { return nil }
        return FileMetadata(fileId: fid, filename: fn, fileSize: fs, chunkCount: cc, sha256Hash: hash, burnAfterRead: d["burn_after_read"] as? Bool ?? false)
    }
}
