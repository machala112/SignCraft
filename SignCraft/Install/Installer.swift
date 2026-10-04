import Foundation
import UIKit

/// Installs a signed IPA using iOS's official over-the-air mechanism:
/// serve a manifest plist + the IPA over local HTTP, then open itms-services.
final class Installer: ObservableObject {
    private let server = LocalHTTPServer()

    enum Error: Swift.Error, LocalizedError {
        case serverFailed
        case noManifestURL
        var errorDescription: String? {
            switch self {
            case .serverFailed: return "Could not start the local install server"
            case .noManifestURL: return "Could not build the install link"
            }
        }
    }

    /// Prepare the server. Returns the itms-services URL to open.
    func prepareInstall(ipaURL: URL, bundleID: String, version: String, name: String) throws -> URL {
        let ipaData = try Data(contentsOf: ipaURL)
        server.serve(path: "/app.ipa", data: ipaData, contentType: "application/octet-stream")
        try server.start()
        guard let base = server.baseURL else { throw Error.serverFailed }

        let manifest: [String: Any] = [
            "items": [[
                "assets": [[
                    "kind": "software-package",
                    "url": "\(base)/app.ipa",
                ]],
                "metadata": [
                    "bundle-identifier": bundleID,
                    "bundle-version": version,
                    "kind": "software",
                    "title": name,
                ],
            ]],
        ]
        let manifestData = try PropertyListSerialization.data(fromPropertyList: manifest,
                                                              format: .xml, options: 0)
        server.serve(path: "/manifest.plist", data: manifestData,
                     contentType: "application/x-plist")
        guard let itms = URL(string:
            "itms-services://?action=download-manifest&url=\(base)/manifest.plist") else {
            throw Error.noManifestURL
        }
        return itms
    }

    func finish() { server.stop() }
}
