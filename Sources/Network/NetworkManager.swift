import Foundation

/// P2P networking over Tor with auto-reconnect, heartbeat, offline queue.
/// Wire-compatible with Python and Android versions.
class NetworkManager {
    private let tor: TorManager
    private var peers: [String: PeerInfo] = [:]
    private var messageQueue: [(peer: String, data: Data, time: Date)] = []
    private var running = false
    private let lock = NSLock()

    var onDataReceived: ((String, Data) -> Void)?
    var onPeerConnected: ((String) -> Void)?
    var onPeerDisconnected: ((String) -> Void)?

    init(tor: TorManager) { self.tor = tor }

    func start() {
        running = true
        DispatchQueue.global(qos: .background).async { self.acceptLoop() }
        DispatchQueue.global(qos: .background).async { self.heartbeatLoop() }
        DispatchQueue.global(qos: .background).async { self.reconnectLoop() }
        DispatchQueue.global(qos: .background).async { self.queueFlushLoop() }
    }

    func stop() {
        running = false
        lock.lock()
        for p in peers.values { p.connection?.close() }
        peers.removeAll()
        lock.unlock()
    }

    func connectToPeer(_ onion: String) async -> Bool {
        if isPeerConnected(onion) { return true }
        guard let conn = tor.connectToOnion(onion, port: 80) else { return false }
        lock.lock()
        peers[onion] = PeerInfo(onion: onion, connection: conn)
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { self.receiveLoop(onion) }
        onPeerConnected?(onion)
        flushQueue(for: onion)
        return true
    }

    func send(to peer: String, data: Data) {
        lock.lock()
        let conn = peers[peer]?.connection
        lock.unlock()
        if let c = conn, c.isConnected, sendFramed(conn: c, data: data) { return }
        // Queue for later delivery
        lock.lock()
        messageQueue.append((peer, data, Date()))
        if messageQueue.count > 1000 { messageQueue.removeFirst() }
        lock.unlock()
    }

    func sendNoQueue(to peer: String, data: Data) {
        lock.lock()
        let conn = peers[peer]?.connection
        lock.unlock()
        if let c = conn { _ = sendFramed(conn: c, data: data) }
    }

    func sendHello(to peer: String, ourOnion: String) {
        let hello: [String: Any] = ["type": "hello", "onion": ourOnion, "version": "1.0"]
        if let data = try? JSONSerialization.data(withJSONObject: hello) { send(to: peer, data: data) }
    }

    func isPeerConnected(_ onion: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return peers[onion]?.connected ?? false
    }

    func disconnect(_ onion: String) {
        lock.lock()
        peers[onion]?.connection?.close()
        peers[onion]?.connected = false
        lock.unlock()
        onPeerDisconnected?(onion)
    }

    // MARK: - Framing (wire-compatible: length(4 BE) + CRC32(4 BE) + data)

    private func sendFramed(conn: SocketConnection, data: Data) -> Bool {
        var header = Data(capacity: 8)
        var length = UInt32(data.count).bigEndian
        var checksum = CRC32.calculate(data).bigEndian
        withUnsafeBytes(of: &length) { header.append(contentsOf: $0) }
        withUnsafeBytes(of: &checksum) { header.append(contentsOf: $0) }
        return conn.send(header + data)
    }

    private func receiveFramed(conn: SocketConnection, timeout: TimeInterval) -> Data? {
        guard let header = conn.receiveExact(count: 8, timeout: timeout) else { return nil }
        let length = header.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self).bigEndian }
        let expectedCRC = header.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self).bigEndian }

        guard length <= 16 * 1024 * 1024, length > 0 else { return nil }
        guard let data = conn.receiveExact(count: Int(length), timeout: timeout) else { return nil }

        let actualCRC = CRC32.calculate(data)
        guard actualCRC == expectedCRC else { return nil }
        return data
    }

    // MARK: - Accept incoming connections

    private func acceptLoop() {
        let serverFd = socket(AF_INET, SOCK_STREAM, 0)
        guard serverFd >= 0 else { return }
        defer { close(serverFd) }

        var opt: Int32 = 1
        setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = tor.hiddenServicePort.bigEndian

        let bindOk = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindOk == 0 else { return }
        listen(serverFd, 10)

        var tv = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(serverFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        while running {
            var clientAddr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFd = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverFd, $0, &len)
                }
            }
            guard clientFd >= 0 else { continue }
            DispatchQueue.global(qos: .userInitiated).async {
                self.handleIncoming(fd: clientFd)
            }
        }
    }

    private func handleIncoming(fd: Int32) {
        let conn = SocketConnection.fromAccepted(fd: fd)
        guard let data = receiveFramed(conn: conn, timeout: 30) else { conn.close(); return }

        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj["type"] as? String == "hello",
              let onion = obj["onion"] as? String
        else { conn.close(); return }

        lock.lock()
        // Close existing connection if any
        peers[onion]?.connection?.close()
        peers[onion] = PeerInfo(onion: onion, connection: conn)
        lock.unlock()

        onPeerConnected?(onion)
        flushQueue(for: onion)
        receiveLoop(onion)
    }

    // MARK: - Receive loop

    private func receiveLoop(_ onion: String) {
        while running {
            lock.lock()
            let conn = peers[onion]?.connection
            let connected = peers[onion]?.connected ?? false
            lock.unlock()
            guard let c = conn, connected else { break }

            guard let data = receiveFramed(conn: c, timeout: 90) else {
                // Timeout — check if still connected
                if !c.isConnected { break }
                continue
            }

            // Control messages
            if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let t = obj["type"] as? String, ["ping", "pong", "heartbeat"].contains(t) {
                if t == "ping" || t == "heartbeat" {
                    let pong: [String: Any] = ["type": "pong", "ts": Date().timeIntervalSince1970]
                    if let d = try? JSONSerialization.data(withJSONObject: pong) { _ = sendFramed(conn: c, data: d) }
                }
                continue
            }

            onDataReceived?(onion, data)
        }

        // Disconnected
        lock.lock()
        peers[onion]?.connected = false
        lock.unlock()
        onPeerDisconnected?(onion)
    }

    // MARK: - Background loops

    private func heartbeatLoop() {
        while running {
            Thread.sleep(forTimeInterval: 30)
            guard running else { break }
            lock.lock()
            let connected = peers.filter { $0.value.connected }.map { $0.key }
            lock.unlock()
            let hb: [String: Any] = ["type": "heartbeat", "ts": Date().timeIntervalSince1970]
            guard let data = try? JSONSerialization.data(withJSONObject: hb) else { continue }
            for peer in connected { sendNoQueue(to: peer, data: data) }
        }
    }

    private func reconnectLoop() {
        while running {
            Thread.sleep(forTimeInterval: 10)
            guard running else { break }
            lock.lock()
            let disconnected = peers.filter { !$0.value.connected && $0.value.reconnectAttempts < 5 }
                .map { ($0.key, $0.value.reconnectAttempts) }
            lock.unlock()

            for (peer, attempts) in disconnected {
                let delay = 5.0 * pow(2.0, Double(attempts))
                lock.lock()
                let lastSeen = peers[peer]?.lastActivity ?? Date.distantPast
                lock.unlock()
                guard Date().timeIntervalSince(lastSeen) >= delay else { continue }

                lock.lock()
                peers[peer]?.reconnectAttempts += 1
                lock.unlock()
                Task { let _ = await connectToPeer(peer) }
            }
        }
    }

    private func queueFlushLoop() {
        while running {
            Thread.sleep(forTimeInterval: 60)
            lock.lock()
            messageQueue.removeAll { Date().timeIntervalSince($0.time) > 86400 }
            lock.unlock()
        }
    }

    private func flushQueue(for peer: String) {
        lock.lock()
        let toSend = messageQueue.filter { $0.peer == peer }
        messageQueue.removeAll { $0.peer == peer }
        lock.unlock()
        for msg in toSend { send(to: peer, data: msg.data) }
    }
}

// MARK: - PeerInfo

class PeerInfo {
    let onion: String
    var connection: SocketConnection?
    var connected: Bool = true
    var reconnectAttempts = 0
    var lastActivity = Date()

    init(onion: String, connection: SocketConnection?) {
        self.onion = onion
        self.connection = connection
    }
}

// MARK: - CRC32 (wire-compatible with Python's zlib.crc32)

enum CRC32 {
    private static let table: [UInt32] = {
        (0..<256).map { i -> UInt32 in
            var crc = UInt32(i)
            for _ in 0..<8 {
                crc = (crc & 1 != 0) ? (0xEDB88320 ^ (crc >> 1)) : (crc >> 1)
            }
            return crc
        }
    }()

    static func calculate(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for byte in data {
            let index = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = table[index] ^ (crc >> 8)
        }
        return crc ^ 0xFFFFFFFF
    }
}

// MARK: - SocketConnection framing extension

extension SocketConnection {
    func sendFramed(_ data: Data) -> Bool {
        var header = Data(capacity: 8)
        var length = UInt32(data.count).bigEndian
        var checksum = CRC32.calculate(data).bigEndian
        withUnsafeBytes(of: &length) { header.append(contentsOf: $0) }
        withUnsafeBytes(of: &checksum) { header.append(contentsOf: $0) }
        return send(header + data)
    }

    func receiveFramed(timeout: TimeInterval) -> Data? {
        guard let header = receiveExact(count: 8, timeout: timeout) else { return nil }
        let length = header.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self).bigEndian }
        let expectedCRC = header.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self).bigEndian }
        guard length <= 16 * 1024 * 1024, length > 0 else { return nil }
        guard let data = receiveExact(count: Int(length), timeout: timeout) else { return nil }
        guard CRC32.calculate(data) == expectedCRC else { return nil }
        return data
    }
}
