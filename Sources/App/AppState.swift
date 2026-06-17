import Foundation
import SwiftUI
import Combine

enum ConnectionStatus: String {
    case disconnected, connecting, connected, failed
}

enum ContactStatus: String, Codable {
    case offline, connecting, connected
}

@MainActor
class AppState: ObservableObject {
    @Published var isUnlocked = false
    @Published var connectionStatus: ConnectionStatus = .disconnected
    @Published var ourOnionAddress = ""
    @Published var ourFingerprint = ""
    @Published var contacts: [Contact] = []
    @Published var currentPeer: String? = nil
    @Published var messages: [String: [ChatMessage]] = [:]
    @Published var groups: [GroupInfo] = []
    @Published var useBridges = false

    var identity: Identity?
    var torManager: TorManager
    var networkManager: NetworkManager?
    var storage: EncryptedStorage
    var sessions: [String: Session] = [:]
    var fileTransfer: FileTransferManager
    var groupManager: GroupManager
    var disappearing: DisappearingManager
    var panicWipe: PanicWipe
    var decoyMode: DecoyMode
    var vanityGenerator: VanityGenerator

    private let dataDir: URL

    init() {
        dataDir = Self.getDataDir()
        torManager = TorManager(dataDir: dataDir)
        storage = EncryptedStorage(dataDir: dataDir)
        fileTransfer = FileTransferManager(dataDir: dataDir)
        groupManager = GroupManager()
        disappearing = DisappearingManager()
        panicWipe = PanicWipe(dataDir: dataDir)
        decoyMode = DecoyMode(dataDir: dataDir)
        vanityGenerator = VanityGenerator()
    }

    // MARK: - Auth

    func unlock(passphrase: String, isNewAccount: Bool) -> Bool {
        if panicWipe.checkPanic(passphrase: passphrase) {
            panicWipe.executeWipe()
            return false
        }
        if decoyMode.isDecoyPassphrase(passphrase) {
            return false
        }
        if isNewAccount {
            storage.reset()
        }
        guard storage.open(passphrase: passphrase) else { return false }
        loadOrCreateIdentity()
        loadContacts()
        loadSessions()
        loadGroups()
        isUnlocked = true
        return true
    }

    // MARK: - Tor

    func connectTor() {
        connectionStatus = .connecting
        torManager.statusCallback = { [weak self] msg, _ in
            Task { @MainActor in self?.connectionStatus = .connecting }
        }
        Task {
            let ok = await torManager.start(useBridges: useBridges)
            if ok {
                connectionStatus = .connected
                ourOnionAddress = torManager.onionAddress
                startNetwork()
                autoConnect()
            } else {
                connectionStatus = .failed
            }
        }
    }

    private func startNetwork() {
        let net = NetworkManager(tor: torManager)
        net.onDataReceived = { [weak self] peer, data in
            Task { @MainActor in self?.onDataReceived(peer: peer, data: data) }
        }
        net.onPeerConnected = { [weak self] peer in
            Task { @MainActor in self?.updateStatus(peer, .connected) }
        }
        net.onPeerDisconnected = { [weak self] peer in
            Task { @MainActor in self?.updateStatus(peer, .offline) }
        }
        net.start()
        networkManager = net
    }

    private func autoConnect() {
        Task {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            for c in contacts where !c.blocked {
                await connectPeer(c.onionAddress)
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    // MARK: - Identity

    private func loadOrCreateIdentity() {
        if let saved = storage.loadIdentity() {
            identity = Identity.fromSaved(saved)
        }
        if identity == nil {
            identity = Identity.generate()
            if let id = identity { storage.saveIdentity(id.export()) }
        }
        ourFingerprint = identity?.getFingerprint() ?? ""
    }

    // MARK: - Contacts

    private func loadContacts() {
        contacts = storage.loadContacts()
        for c in contacts where !c.blocked {
            messages[c.onionAddress] = storage.loadMessages(peer: c.onionAddress)
        }
    }

    private func loadSessions() {
        for c in contacts where !c.blocked {
            if let state = storage.loadSession(peer: c.onionAddress), let id = identity {
                let s = Session(identity: id, peerOnion: c.onionAddress)
                if s.importState(state) { sessions[c.onionAddress] = s }
            }
        }
    }

    private func loadGroups() {
        if let state = storage.loadSession(peer: "__groups__") {
            groupManager.importState(state)
            groups = Array(groupManager.groups.values)
        }
    }

    func addContact(_ address: String) {
        let addr = address.replacingOccurrences(of: ".onion", with: "").trimmingCharacters(in: .whitespaces)
        guard addr.count >= 10, !contacts.contains(where: { $0.onionAddress == addr }) else { return }
        let c = Contact(onionAddress: addr, displayName: String(addr.prefix(12)) + "...", addedAt: Date())
        contacts.append(c)
        storage.saveContact(c)
        Task { await connectPeer(addr) }
    }

    func deleteContact(_ addr: String) {
        contacts.removeAll { $0.onionAddress == addr }
        storage.removeContact(addr)
        storage.deleteMessages(peer: addr)
        storage.deleteSession(peer: addr)
        sessions.removeValue(forKey: addr)
        messages.removeValue(forKey: addr)
        networkManager?.disconnect(addr)
    }

    func blockContact(_ addr: String) {
        if let i = contacts.firstIndex(where: { $0.onionAddress == addr }) {
            contacts[i].blocked = true
            storage.saveContact(contacts[i])
        }
        networkManager?.disconnect(addr)
    }

    // MARK: - Messaging

    func sendMessage(to peer: String, text: String) {
        guard let session = sessions[peer], session.established else {
            Task { await connectPeer(peer) }
            return
        }
        guard let encrypted = session.encryptMessage(text) else { return }
        networkManager?.send(to: peer, data: encrypted)
        saveSession(peer)

        let msg = ChatMessage(id: UUID().uuidString, sender: ourOnionAddress, text: text, timestamp: Date(), isOurs: true)
        appendMsg(msg, peer: peer)
        storage.saveMessage(peer: peer, message: msg)
        disappearing.schedule(msgId: msg.id, peer: peer)
    }

    // MARK: - Connection

    func connectPeer(_ addr: String) async {
        guard let net = networkManager, !net.isPeerConnected(addr) else { return }
        updateStatus(addr, .connecting)
        let ok = await net.connectToPeer(addr)
        if ok {
            net.sendHello(to: addr, ourOnion: ourOnionAddress)
            initiateKex(addr)
        } else {
            updateStatus(addr, .offline)
        }
    }

    private func initiateKex(_ peer: String) {
        if sessions[peer]?.established == true {
            updateStatus(peer, .connected)
            return
        }
        guard let id = identity else { return }
        let s = Session(identity: id, peerOnion: peer)
        sessions[peer] = s
        networkManager?.send(to: peer, data: s.createKeyExchangeInit())
    }

    // MARK: - Receive

    private func onDataReceived(peer: String, data: Data) {
        guard !data.isEmpty, data.first != 0x00 else { return }
        if contacts.first(where: { $0.onionAddress == peer })?.blocked == true { return }

        if let msg = ProtocolMessage.deserialize(data) {
            handleProtocol(peer: peer, msg: msg, raw: data)
        } else {
            handleJson(peer: peer, data: data)
        }
    }

    private func handleProtocol(peer: String, msg: ProtocolMessage, raw: Data) {
        switch msg.msgType {
        case .keyExchange: handleKex(peer, raw)
        case .keyExchangeReply: handleKexReply(peer, raw)
        case .text: handleText(peer, raw)
        case .fileMeta: handleFileMeta(peer, msg)
        case .fileChunk: handleFileChunk(peer, msg)
        case .sessionReset: handleSessionReset(peer)
        case .ping: sendPong(peer)
        default: break
        }
    }

    private func handleKex(_ peer: String, _ data: Data) {
        guard let id = identity else { return }
        let s = Session(identity: id, peerOnion: peer)
        guard let reply = s.handleKeyExchangeInit(data) else { return }
        sessions[peer] = s
        saveSession(peer)
        networkManager?.send(to: peer, data: reply)
        updateStatus(peer, .connected)
    }

    private func handleKexReply(_ peer: String, _ data: Data) {
        guard let s = sessions[peer], s.handleKeyExchangeReply(data) else { return }
        saveSession(peer)
        updateStatus(peer, .connected)
    }

    private func handleText(_ peer: String, _ data: Data) {
        guard let s = sessions[peer], s.established, let text = s.decryptMessage(data) else {
            initiateKex(peer)
            return
        }
        saveSession(peer)
        let msg = ChatMessage(id: UUID().uuidString, sender: peer, text: text, timestamp: Date(), isOurs: false)
        appendMsg(msg, peer: peer)
        storage.saveMessage(peer: peer, message: msg)
        disappearing.schedule(msgId: msg.id, peer: peer)
        // ACK
        if let pm = ProtocolMessage.deserialize(data), let session = sessions[peer] {
            let ack = session.createAck(msgId: pm.msgId)
            networkManager?.sendNoQueue(to: peer, data: ack)
        }
    }

    private func handleFileMeta(_ peer: String, _ msg: ProtocolMessage) {
        guard let meta = FileMetadata.deserialize(msg.payload) else { return }
        fileTransfer.startReceive(metadata: meta)
        appendSystem("Receiving: \(meta.filename) (\(meta.fileSize / 1024)KB)", peer: peer)
    }

    private func handleFileChunk(_ peer: String, _ msg: ProtocolMessage) {
        guard msg.payload.count >= 20, let s = sessions[peer], let r = s.ratchet else { return }
        let fileId = String(bytes: msg.payload.prefix(16).filter { $0 != 0 }, encoding: .utf8) ?? ""
        let idx: UInt32 = msg.payload.advanced(by: 16).withUnsafeBytes { $0.load(as: UInt32.self) }
        let chunk = msg.payload.dropFirst(20)
        let key = CryptoEngine.hkdfDerive(ikm: r.rootKey, salt: Data("file-transfer".utf8), info: Data(fileId.utf8))
        if fileTransfer.receiveChunk(fileId: fileId, index: Int(idx), data: Data(chunk), key: key) {
            appendSystem("File received: \(fileId)", peer: peer)
        }
    }

    private func handleSessionReset(_ peer: String) {
        sessions.removeValue(forKey: peer)
        storage.deleteSession(peer: peer)
        initiateKex(peer)
        appendSystem("Session re-established", peer: peer)
    }

    private func sendPong(_ peer: String) {
        let p = ProtocolMessage(msgType: .pong, payload: Data(), timestamp: Date(), msgId: 0)
        networkManager?.sendNoQueue(to: peer, data: p.serialize())
    }

    private func handleJson(peer: String, data: Data) {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = obj["type"] as? String else { return }
        switch type {
        case "hello":
            let real = obj["onion"] as? String ?? peer
            updateStatus(real, .connected)
            if !contacts.contains(where: { $0.onionAddress == real }) {
                let c = Contact(onionAddress: real, displayName: String(real.prefix(12)) + "...", addedAt: Date())
                contacts.append(c)
                storage.saveContact(c)
            }
        case "group_invite":
            if let gid = groupManager.handleInvite(obj, ourOnion: ourOnionAddress) {
                if let g = groupManager.groups[gid] { groups.append(g) }
            }
        case "group_message":
            if let gid = obj["group_id"] as? String, let hex = obj["data"] as? String, let d = Data(hexString: hex) {
                if let m = groupManager.decryptMessage(groupId: gid, data: d) {
                    appendSystem("[\(m.sender.prefix(8))]: \(m.text)", peer: "group:\(gid)")
                }
            }
        case "sender_key_distribution":
            if let gid = obj["group_id"] as? String, let sender = obj["sender"] as? String, let key = obj["key"] as? String {
                groupManager.updatePeerKey(groupId: gid, peer: sender, keyHex: key, iteration: obj["iteration"] as? Int ?? 0)
            }
        case "address_change":
            if let newAddr = obj["new_address"] as? String, let i = contacts.firstIndex(where: { $0.onionAddress == peer }) {
                let old = contacts[i].onionAddress
                contacts[i].onionAddress = newAddr
                storage.saveContact(contacts[i])
                if let s = sessions.removeValue(forKey: old) { sessions[newAddr] = s; saveSession(newAddr) }
                appendSystem("Contact moved to \(newAddr.prefix(16))...onion", peer: newAddr)
            }
        case "disappearing_config":
            let en = obj["enabled"] as? Bool ?? false
            let sec = obj["seconds"] as? Int ?? 300
            disappearing.setConfig(peer: peer, enabled: en, seconds: sec)
        default: break
        }
    }

    // MARK: - Stealth

    func setPanic(_ pass: String) { panicWipe.setPanicPassphrase(pass) }
    func setDecoy(_ pass: String) { decoyMode.setupDecoy(pass) }
    func setDisappearing(peer: String, enabled: Bool, seconds: Int) {
        disappearing.setConfig(peer: peer, enabled: enabled, seconds: seconds)
        let d: [String: Any] = ["type": "disappearing_config", "enabled": enabled, "seconds": seconds]
        if let data = try? JSONSerialization.data(withJSONObject: d) { networkManager?.send(to: peer, data: data) }
    }
    func resetSession(_ peer: String) {
        if let s = sessions[peer] { networkManager?.sendNoQueue(to: peer, data: s.createSessionReset()) }
        sessions.removeValue(forKey: peer)
        storage.deleteSession(peer: peer)
        initiateKex(peer)
    }
    func generateVanity(prefix: String) {
        vanityGenerator.start(prefix: prefix) { [weak self] addr, key in
            guard let self, let addr, let key else { return }
            VanityGenerator.writeKeyFiles(key: key, dir: self.dataDir.appendingPathComponent("hidden_service"))
            let old = self.ourOnionAddress
            Task { @MainActor in self.ourOnionAddress = addr }
            self.broadcastAddressChange(old: old, new: addr)
        }
    }

    private func broadcastAddressChange(old: String, new: String) {
        let d: [String: Any] = ["type": "address_change", "old_address": old, "new_address": new]
        guard let data = try? JSONSerialization.data(withJSONObject: d) else { return }
        for c in contacts where !c.blocked { networkManager?.send(to: c.onionAddress, data: data) }
    }

    // MARK: - File

    func sendFile(to peer: String, url: URL, burn: Bool = false) {
        guard let s = sessions[peer], s.established, let r = s.ratchet else { return }
        guard let meta = fileTransfer.prepareSend(url: url, burn: burn) else { return }
        let metaMsg = ProtocolMessage(msgType: .fileMeta, payload: meta.serialize(), timestamp: Date(), msgId: Int(Date().timeIntervalSince1970 * 1000))
        networkManager?.send(to: peer, data: metaMsg.serialize())
        let key = CryptoEngine.hkdfDerive(ikm: r.rootKey, salt: Data("file-transfer".utf8), info: Data(meta.fileId.utf8))
        Task {
            for i in 0..<meta.chunkCount {
                guard let chunk = fileTransfer.getChunk(url: url, fileId: meta.fileId, index: i, key: key) else { break }
                var payload = Data(meta.fileId.padding(toLength: 16, withPad: "\0", startingAt: 0).utf8)
                withUnsafeBytes(of: UInt32(i)) { payload.append(contentsOf: $0) }
                payload.append(chunk)
                let cm = ProtocolMessage(msgType: .fileChunk, payload: payload, timestamp: Date(), msgId: 0)
                networkManager?.send(to: peer, data: cm.serialize())
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            appendSystem("File sent: \(meta.filename)", peer: peer)
        }
    }

    // MARK: - Group

    func createGroup(name: String, members: [String]) {
        let g = groupManager.createGroup(name: name, ourOnion: ourOnionAddress)
        groups.append(g)
        for m in members {
            if let invite = groupManager.addMember(groupId: g.groupId, member: m, name: String(m.prefix(12)) + "...", ourOnion: ourOnionAddress),
               let data = try? JSONSerialization.data(withJSONObject: invite) {
                networkManager?.send(to: m, data: data)
            }
        }
        saveGroupState()
    }

    func sendGroupMessage(groupId: String, text: String) {
        guard let encrypted = groupManager.encrypt(groupId: groupId, text: text, ourOnion: ourOnionAddress) else { return }
        guard let g = groupManager.groups[groupId] else { return }
        let env: [String: Any] = ["type": "group_message", "group_id": groupId, "data": encrypted.hexString]
        guard let data = try? JSONSerialization.data(withJSONObject: env) else { return }
        for m in g.members where m.onionAddress != ourOnionAddress { networkManager?.send(to: m.onionAddress, data: data) }
        appendSystem("[You]: \(text)", peer: "group:\(groupId)")
        saveGroupState()
    }

    private func saveGroupState() { storage.saveSession(peer: "__groups__", state: groupManager.exportState()) }

    // MARK: - Helpers

    private func saveSession(_ peer: String) {
        if let s = sessions[peer] { storage.saveSession(peer: peer, state: s.exportState()) }
    }
    private func appendMsg(_ msg: ChatMessage, peer: String) {
        if messages[peer] == nil { messages[peer] = [] }
        messages[peer]?.append(msg)
    }
    private func appendSystem(_ text: String, peer: String) {
        appendMsg(ChatMessage(id: UUID().uuidString, sender: "system", text: text, timestamp: Date(), isOurs: false, isSystem: true), peer: peer)
    }
    private func updateStatus(_ peer: String, _ status: ContactStatus) {
        if let i = contacts.firstIndex(where: { $0.onionAddress == peer }) { contacts[i].status = status }
    }

    static func getDataDir() -> URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Epiphyte")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}
