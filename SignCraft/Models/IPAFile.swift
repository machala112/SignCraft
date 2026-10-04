import Foundation

/// An IPA imported into the app, stored in the sandbox.
struct IPAFile: Identifiable {
    let id = UUID()
    let fileName: String
    let localURL: URL
    let size: Int64
    let importedAt: Date

    var displaySize: String {
        let mb = Double(size) / 1_000_000
        return String(format: "%.1f MB", mb)
    }
}

/// A stored .p12 (file in sandbox; password in Keychain).
struct StoredCertificate: Identifiable {
    let id: UUID
    let label: String
    let fileName: String
    let localURL: URL
    let importedAt: Date
}

/// A stored .mobileprovision (file in sandbox + parsed metadata).
struct StoredProfile: Identifiable {
    let id: UUID
    let profile: ProvisioningProfile
    let localURL: URL
    let importedAt: Date
}
