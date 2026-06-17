import Foundation
#if os(iOS)
import UIKit
#endif

/// Manages embedded Tor connection — no external apps needed.
/// iOS: Runs Tor in-process using bundled tor static library.
/// macOS: Launches tor binary from bundle or PATH.
///
/// This approach embeds Tor directly so the user only needs to install Epiphyte.
/// For Xcode build, link against Tor.framework (from iCepa/Tor.framework).
class TorManager {
    let dataDir: URL
    var onionAddress = ""
    var socksPort: UInt16 = 9150
    var controlPort: UInt16 = 9151
    var hiddenServicePort: UInt16 = 7777
    var statusCallback: ((String, Int) -> Void)?
    private(set) var isRunning = false
    private var controlSocket: SocketConnection?

    #if os(macOS)
    private var torProcess: Process?
    #endif

    static let defaultBridges = [
        "obfs4 193.11.166.194:27025 2D82C2E354D531A68469ADA8F719C297D76B9F5D cert=0RWSTSwuEqwd/7HNqs3eP/JDkMGr0hEUBINIoJ2A8iNpSMZaZi2AoIkjB4NI iat-mode=0",
        "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNnLZTjnDROfvzjyJkLknN+5vxGVY/VfhBq iat-mode=1",
        "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/cB0dPbVDynpUhJsNEsFif iat-mode=0",
    ]

    init(dataDir: URL) {
        self.dataDir = dataDir
    }

    func start(useBridges: Bool) async -> Bool {
        statusCallback?("Starting Tor...", 10)

        socksPort = findFreePort(preferred: 9150)
        controlPort = findFreePort(preferred: 9151)
        hiddenServicePort = findFreePort(preferred: 7777)

        let torDataDir = dataDir.appendingPathComponent("tor_data")
        let hsDir = dataDir.appendingPathComponent("hidden_service")
        try? FileManager.default.createDirectory(at: torDataDir, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: hsDir, withIntermediateDirectories: true)

        let torrc = buildTorrc(torDataDir: torDataDir, hsDir: hsDir, useBridges: useBridges)
        let torrcPath = torDataDir.appendingPathComponent("torrc")
        try? torrc.write(to: torrcPath, atomically: true, encoding: .utf8)

        // Find and launch Tor
        guard let torBin = findTorBinary() else {
            statusCallback?("Tor binary not found in bundle", -1)
            return false
        }

        statusCallback?("Launching Tor...", 15)

        let launched = launchTor(binary: torBin, torrc: torrcPath)
        guard launched else {
            statusCallback?("Failed to start Tor", -1)
            return false
        }

        // Wait for bootstrap
        statusCallback?("Bootstrapping...", 20)
        let bootstrapped = await waitForBootstrap(timeout: 180)
        guard bootstrapped else {
            statusCallback?("Tor bootstrap timeout", -1)
            stop()
            return false
        }

        // Read hidden service address
        await readOnionAddress(hsDir: hsDir)
        isRunning = true
        statusCallback?("Connected", 100)
        return true
    }

    // MARK: - Tor binary

    private func findTorBinary() -> URL? {
        // 1. Check app bundle (for iOS/macOS with embedded tor)
        if let bundled = Bundle.main.url(forResource: "tor", withExtension: nil) {
            return bundled
        }
        // 2. Check Frameworks bundle (Tor.framework ships the binary)
        if let fw = Bundle.main.privateFrameworksURL {
            let torInFw = fw.appendingPathComponent("Tor.framework/tor")
            if FileManager.default.isExecutableFile(atPath: torInFw.path) {
                return torInFw
            }
        }
        #if os(macOS)
        // 3. Check system paths (macOS only)
        let systemPaths = ["/opt/homebrew/bin/tor", "/usr/local/bin/tor", "/usr/bin/tor"]
        for p in systemPaths {
            if FileManager.default.isExecutableFile(atPath: p) {
                return URL(fileURLWithPath: p)
            }
        }
        #endif
        // 4. Check app support directory (downloaded tor)
        let downloadedTor = dataDir.appendingPathComponent("bin/tor")
        if FileManager.default.isExecutableFile(atPath: downloadedTor.path) {
            return downloadedTor
        }
        return nil
    }

    private func launchTor(binary: URL, torrc: URL) -> Bool {
        #if os(macOS)
        let process = Process()
        process.executableURL = binary
        process.arguments = ["-f", torrc.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            torProcess = process
            // Check immediate crash
            Thread.sleep(forTimeInterval: 1)
            return process.isRunning
        } catch {
            return false
        }
        #else
        // iOS: Launch tor in a background thread using the C function
        // The tor binary must be compiled as a static library and linked
        // Use tor_main_configuration_new/tor_run_main from libtor
        DispatchQueue.global(qos: .background).async {
            self.runTorInProcess(torrc: torrc)
        }
        // Give it a moment to start
        Thread.sleep(forTimeInterval: 2)
        return true
        #endif
    }

    #if os(iOS)
    /// Run Tor in-process on iOS.
    /// This requires linking against libtor.a (static Tor library).
    /// The tor_main() function is called directly — same approach as Onion Browser.
    private func runTorInProcess(torrc: URL) {
        // tor_main is provided by the linked Tor.framework or libtor.a
        // Arguments: ["tor", "-f", "/path/to/torrc"]
        let args = ["tor", "-f", torrc.path]
        let cArgs = args.map { strdup($0) } + [nil]
        defer { cArgs.compactMap { $0 }.forEach { free($0) } }

        // Call tor_main — this blocks until Tor exits
        // In production build, this is linked from Tor.framework
        #if canImport(TorFramework)
        tor_main(Int32(args.count), cArgs)
        #else
        // Fallback: try dlopen approach
        typealias TorMainFunc = @convention(c) (Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
        if let handle = dlopen(nil, RTLD_NOW),
           let sym = dlsym(handle, "tor_main") {
            let torMain = unsafeBitCast(sym, to: TorMainFunc.self)
            var mutableCArgs = cArgs
            _ = torMain(Int32(args.count), &mutableCArgs)
        }
        #endif
    }
    #endif

    // MARK: - Bootstrap

    private func waitForBootstrap(timeout: Int) async -> Bool {
        let start = Date()
        while Date().timeIntervalSince(start) < Double(timeout) {
            try? await Task.sleep(nanoseconds: 2_000_000_000)

            if let sock = SocketConnection.connectDirect(host: "127.0.0.1", port: controlPort) {
                // Authenticate (cookie auth or empty)
                sock.send(Data("AUTHENTICATE \"\"\r\n".utf8))
                guard let authResp = sock.receive(timeout: 5),
                      let authStr = String(data: authResp, encoding: .utf8),
                      authStr.contains("250") else {
                    sock.close()
                    continue
                }

                // Check bootstrap progress
                sock.send(Data("GETINFO status/bootstrap-phase\r\n".utf8))
                if let statusResp = sock.receive(timeout: 5),
                   let statusStr = String(data: statusResp, encoding: .utf8) {
                    sock.close()

                    if statusStr.contains("PROGRESS=100") {
                        return true
                    }

                    // Report progress
                    if let range = statusStr.range(of: #"PROGRESS=(\d+)"#, options: .regularExpression) {
                        let match = statusStr[range]
                        let numStr = match.replacingOccurrences(of: "PROGRESS=", with: "")
                        if let pct = Int(numStr) {
                            statusCallback?("Bootstrapping... \(pct)%", 20 + pct * 7 / 10)
                        }
                    }
                } else {
                    sock.close()
                }
            }

            #if os(macOS)
            if let p = torProcess, !p.isRunning { return false }
            #endif
        }
        return false
    }

    // MARK: - Hidden service

    private func readOnionAddress(hsDir: URL) async {
        let hostnameFile = hsDir.appendingPathComponent("hostname")
        for _ in 0..<30 {
            if let data = try? String(contentsOf: hostnameFile, encoding: .utf8) {
                var addr = data.trimmingCharacters(in: .whitespacesAndNewlines)
                if addr.hasSuffix(".onion") { addr = String(addr.dropLast(6)) }
                if !addr.isEmpty {
                    onionAddress = addr
                    return
                }
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }

    // MARK: - Connections

    func connectToOnion(_ address: String, port: UInt16 = 80) -> SocketConnection? {
        let fullAddr = address.hasSuffix(".onion") ? address : address + ".onion"
        return SocketConnection.connectViaSocks(host: fullAddr, port: port, socksPort: socksPort)
    }

    func stop() {
        isRunning = false
        controlSocket?.close()
        #if os(macOS)
        torProcess?.terminate()
        torProcess = nil
        #endif
    }

    // MARK: - Torrc

    private func buildTorrc(torDataDir: URL, hsDir: URL, useBridges: Bool) -> String {
        var lines = [
            "SocksPort \(socksPort)",
            "ControlPort \(controlPort)",
            "DataDirectory \(torDataDir.path)",
            "CookieAuthentication 1",
            "AvoidDiskWrites 1",
            "HiddenServiceDir \(hsDir.path)",
            "HiddenServicePort 80 127.0.0.1:\(hiddenServicePort)",
            "HiddenServiceVersion 3",
            "CircuitBuildTimeout 60",
            "LearnCircuitBuildTimeout 0",
            "NumEntryGuards 3",
        ]

        if useBridges {
            lines.append("UseBridges 1")
            // On iOS, obfs4proxy is bundled in the app
            if let obfs4 = Bundle.main.url(forResource: "obfs4proxy", withExtension: nil) {
                lines.append("ClientTransportPlugin obfs4 exec \(obfs4.path)")
            }
            for bridge in Self.defaultBridges {
                lines.append("Bridge \(bridge)")
            }
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - Utility

    func findFreePort(preferred: UInt16) -> UInt16 {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return preferred }
        defer { close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = preferred.bigEndian

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bindResult == 0 { return preferred }

        addr.sin_port = 0
        let bindResult2 = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult2 == 0 else { return preferred }

        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(sock, $0, &len)
            }
        }
        return UInt16(bigEndian: addr.sin_port)
    }
}
