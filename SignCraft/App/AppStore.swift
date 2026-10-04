import Foundation
import Security
import SwiftUI

/// Central state: imported IPAs, certificates (.p12) and profiles.
final class AppStore: ObservableObject {
    @Published var ipas: [IPAFile] = []
    @Published var certificates: [StoredCertificate] = []
    @Published var profiles: [StoredProfile] = []

    private let fm = FileManager.default

    init() {
        for dir in ["IPAs", "Certs", "Profiles"] {
            try? fm.createDirectory(at: baseDir.appendingPathComponent(dir),
                                    withIntermediateDirectories: true)
        }
        reload()
    }

    private var baseDir: URL {
        fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    // MARK: - Import

    func importIPA(from url: URL) throws {
        let dest = baseDir.appendingPathComponent("IPAs/\(url.lastPathComponent)")
        if fm.fileExists(atPath: dest.path) { try fm.removeItem(at: dest) }
        try fm.copyItem(at: url, to: dest)
        reload()
    }

    func importP12(from url: URL, password: String, label: String) throws {
        let data = try Data(contentsOf: url)
        // Validate before storing.
        _ = try SigningIdentity.importP12(data, password: password, label: label)
        let id = UUID()
        let dest = baseDir.appendingPathComponent("Certs/\(id.uuidString).p12")
        try data.write(to: dest)
        try savePassword(password, for: id)
        reload()
    }

    func importProfile(from url: URL) throws {
        let data = try Data(contentsOf: url)
        let profile = try ProvisioningProfile.parse(data, fileName: url.lastPathComponent)
        let id = UUID()
        let dest = baseDir.appendingPathComponent("Profiles/\(id.uuidString).mobileprovision")
        try data.write(to: dest)
        reload()
    }

    func deleteIPA(_ ipa: IPAFile) {
        try? fm.removeItem(at: ipa.localURL)
        reload()
    }

    func deleteCertificate(_ cert: StoredCertificate) {
        try? fm.removeItem(at: cert.localURL)
        deletePassword(for: cert.id)
        reload()
    }

    func deleteProfile(_ p: StoredProfile) {
        try? fm.removeItem(at: p.localURL)
        reload()
    }

    // MARK: - Resolve for signing

    func identity(for cert: StoredCertificate) throws -> SigningIdentity {
        let data = try Data(contentsOf: cert.localURL)
        let password = try loadPassword(for: cert.id)
        return try SigningIdentity.importP12(data, password: password, label: cert.label)
    }

    // MARK: - Keychain (p12 passwords)

    private func keychainKey(for id: UUID) -> String { "signcraft-p12-\(id.uuidString)" }

    private func savePassword(_ password: String, for id: UUID) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey(for: id),
            kSecValueData as String: Data(password.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw SigningIdentity.Error.importFailed("keychain save failed") }
    }

    private func loadPassword(for id: UUID) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey(for: id),
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let pw = String(data: data, encoding: .utf8) else {
            throw SigningIdentity.Error.importFailed("keychain read failed")
        }
        return pw
    }

    private func deletePassword(for id: UUID) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey(for: id),
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Reload

    func reload() {
        ipas = loadIPAs()
        certificates = loadCerts()
        profiles = loadProfiles()
    }

    private func loadIPAs() -> [IPAFile] {
        let dir = baseDir.appendingPathComponent("IPAs")
        let urls = (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey])) ?? []
        return urls.filter { $0.pathExtension.lowercased() == "ipa" }.map { url in
            let vals = try? url.resourceValues(forKeys: [.fileSizeKey, .creationDateKey])
            return IPAFile(fileName: url.lastPathComponent, localURL: url,
                           size: Int64(vals?.fileSize ?? 0),
                           importedAt: vals?.creationDate ?? Date())
        }.sorted { $0.importedAt > $1.importedAt }
    }

    private func loadCerts() -> [StoredCertificate] {
        let dir = baseDir.appendingPathComponent("Certs")
        let urls = (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.creationDateKey])) ?? []
        return urls.filter { $0.pathExtension.lowercased() == "p12" }.compactMap { url in
            guard let id = UUID(uuidString: url.deletingPathExtension().lastPathComponent) else { return nil }
            let vals = try? url.resourceValues(forKeys: [.creationDateKey])
            return StoredCertificate(id: id, label: "Certificate", fileName: url.lastPathComponent,
                                     localURL: url, importedAt: vals?.creationDate ?? Date())
        }.sorted { $0.importedAt > $1.importedAt }
    }

    private func loadProfiles() -> [StoredProfile] {
        let dir = baseDir.appendingPathComponent("Profiles")
        let urls = (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.creationDateKey])) ?? []
        return urls.filter { $0.pathExtension.lowercased() == "mobileprovision" }.compactMap { url in
            guard let id = UUID(uuidString: url.deletingPathExtension().lastPathComponent),
                  let data = try? Data(contentsOf: url),
                  let profile = try? ProvisioningProfile.parse(data, fileName: url.lastPathComponent) else { return nil }
            let vals = try? url.resourceValues(forKeys: [.creationDateKey])
            return StoredProfile(id: id, profile: profile, localURL: url,
                                 importedAt: vals?.creationDate ?? Date())
        }.sorted { $0.importedAt > $1.importedAt }
    }
}
