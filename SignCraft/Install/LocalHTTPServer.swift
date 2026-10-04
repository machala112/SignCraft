import Foundation
import Network

/// Tiny HTTP server (localhost/Wi-Fi) that serves the signed IPA and the OTA
/// manifest so iOS can install the app via itms-services. Everything stays on
/// the device / local network.
final class LocalHTTPServer {
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "signcraft.http")
    private var files: [String: (data: Data, contentType: String)] = [:]

    var port: UInt16 = 0

    var baseURL: URL? {
        guard port != 0, let ip = wifiIPAddress() else { return nil }
        return URL(string: "http://\(ip):\(port)")
    }

    func serve(path: String, data: Data, contentType: String) {
        files[path] = (data, contentType)
    }

    func start() throws {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        listener = try NWListener(using: params, on: 0)
        listener?.newConnectionHandler = { [weak self] conn in
            self?.handle(conn)
        }
        listener?.stateUpdateHandler = { state in
            if case .failed(let e) = state { print("listener failed: \(e)") }
        }
        listener?.start(queue: queue)
        // Read the bound port.
        var tries = 0
        while port == 0 && tries < 50 {
            if let p = listener?.port, p.rawValue != 0 { port = p.rawValue }
            else { usleep(20_000); tries += 1 }
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        port = 0
    }

    private func handle(_ conn: NWConnection) {
        conn.stateUpdateHandler = { state in
            if case .ready = state { self.readRequest(conn) }
        }
        conn.start(queue: queue)
    }

    private func readRequest(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
            guard let self, let data, let req = String(data: data, encoding: .utf8) else {
                conn.cancel(); return
            }
            let path = req.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
            let clean = path.split(separator: "?").first.map(String.init) ?? "/"
            if let file = self.files[clean] {
                var header = "HTTP/1.1 200 OK\r\nContent-Type: \(file.contentType)\r\nContent-Length: \(file.data.count)\r\nConnection: close\r\n\r\n"
                var resp = Data(header.utf8)
                resp += file.data
                conn.send(content: resp, completion: .contentProcessed { _ in conn.cancel() })
            } else {
                let body = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                conn.send(content: Data(body.utf8), completion: .contentProcessed { _ in conn.cancel() })
            }
        }
    }

    /// Device's Wi-Fi IPv4 address.
    func wifiIPAddress() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let iface = ptr.pointee
            guard iface.ifa_addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: iface.ifa_name)
            if name == "en0" || name == "en1" {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let len = socklen_t(iface.ifa_addr.pointee.sa_len)
                if getnameinfo(iface.ifa_addr, len, &host, socklen_t(host.count),
                               nil, 0, NI_NUMERICHOST) == 0 {
                    return String(cString: host)
                }
            }
        }
        return nil
    }
}
