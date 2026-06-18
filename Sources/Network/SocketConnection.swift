import Foundation

/// Low-level socket wrapper for TCP connections.
/// Supports both outbound and inbound (accepted) connections.
class SocketConnection {
    private var fd: Int32 = -1
    private let lock = NSLock()

    private init(fd: Int32) { self.fd = fd }

    /// Accept an incoming connection from a server socket fd.
    static func fromAccepted(fd: Int32) -> SocketConnection {
        return SocketConnection(fd: fd)
    }

    /// Connect directly to a host:port (TCP).
    static func connectDirect(host: String, port: UInt16) -> SocketConnection? {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return nil }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr(host)
        addr.sin_port = port.bigEndian

        // Set timeout
        var timeout = timeval(tv_sec: 90, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else { Darwin.close(sock); return nil }
        return SocketConnection(fd: sock)
    }

    /// Connect via SOCKS5 proxy (Tor).
    static func connectViaSocks(host: String, port: UInt16, socksPort: UInt16) -> SocketConnection? {
        guard let conn = connectDirect(host: "127.0.0.1", port: socksPort) else { return nil }

        // SOCKS5 handshake: version=5, 1 method, no auth
        conn.send(Data([0x05, 0x01, 0x00]))
        guard let resp1 = conn.receive(timeout: 10),
              resp1.count >= 2, resp1[0] == 0x05, resp1[1] == 0x00 else {
            conn.close()
            return nil
        }

        // Connect request with domain name
        let hostBytes = [UInt8](host.utf8)
        var req = Data([0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)])
        req.append(contentsOf: hostBytes)
        req.append(UInt8(port >> 8))
        req.append(UInt8(port & 0xFF))
        conn.send(req)

        // Read response (minimum 10 bytes)
        guard let resp2 = conn.receiveExact(count: 10, timeout: 90),
              resp2.count >= 10, resp2[1] == 0x00 else {
            conn.close()
            return nil
        }

        return conn
    }

    /// Send data. Returns true on success.
    @discardableResult
    func send(_ data: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard fd >= 0 else { return false }

        return data.withUnsafeBytes { buffer -> Bool in
            guard let ptr = buffer.baseAddress else { return false }
            var sent = 0
            while sent < data.count {
                let n = Darwin.send(fd, ptr.advanced(by: sent), data.count - sent, 0)
                if n <= 0 { return false }
                sent += n
            }
            return true
        }
    }

    /// Receive up to 65536 bytes with timeout.
    func receive(timeout: TimeInterval) -> Data? {
        guard fd >= 0 else { return nil }
        setReadTimeout(timeout)

        var buffer = [UInt8](repeating: 0, count: 65536)
        let n = recv(fd, &buffer, buffer.count, 0)
        guard n > 0 else { return nil }
        return Data(buffer[..<n])
    }

    /// Receive exactly `count` bytes.
    func receiveExact(count: Int, timeout: TimeInterval) -> Data? {
        guard fd >= 0 else { return nil }
        setReadTimeout(timeout)

        var buffer = Data(capacity: count)
        while buffer.count < count {
            var chunk = [UInt8](repeating: 0, count: count - buffer.count)
            let n = recv(fd, &chunk, chunk.count, 0)
            guard n > 0 else { return nil }
            buffer.append(contentsOf: chunk[..<n])
        }
        return buffer
    }

    /// Check if socket is still alive.
    var isConnected: Bool {
        guard fd >= 0 else { return false }
        var error: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)
        return error == 0
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }

    private func setReadTimeout(_ seconds: TimeInterval) {
        var timeout = timeval(tv_sec: Int(seconds), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }

    deinit { close() }
}
