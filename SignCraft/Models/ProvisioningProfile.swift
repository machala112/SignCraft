import Foundation

/// A parsed .mobileprovision profile.
struct ProvisioningProfile: Identifiable {
    let id = UUID()
    let fileName: String
    let name: String
    let teamIdentifier: String
    let teamName: String
    let expiration: Date
    /// e.g. "ABCDE12345.*" or "ABCDE12345.com.example.app"
    let applicationIdentifier: String
    let entitlements: [String: Any]
    let provisionedDevices: [String]

    var isExpired: Bool { expiration < Date() }

    enum Error: Swift.Error, LocalizedError {
        case parseFailed
        case missingFields
        var errorDescription: String? {
            switch self {
            case .parseFailed: return "Could not parse provisioning profile"
            case .missingFields: return "Profile is missing required fields"
            }
        }
    }

    /// A .mobileprovision is a CMS-signed plist; the plist XML/binary is
    /// embedded verbatim, so we scan for it instead of CMS-decoding.
    static func parse(_ data: Data, fileName: String) throws -> ProvisioningProfile {
        let bytes = [UInt8](data)
        var plistStart: Int?
        // Look for XML plist magic, else binary plist magic.
        let xmlMagic: [UInt8] = Array("<?xml".utf8)
        outer: for i in 0..<(bytes.count - xmlMagic.count) {
            for j in 0..<xmlMagic.count where bytes[i + j] != xmlMagic[j] { continue outer }
            plistStart = i
            break
        }
        if plistStart == nil {
            let binMagic: [UInt8] = Array("bplist00".utf8)
            outer2: for i in 0..<(bytes.count - binMagic.count) {
                for j in 0..<binMagic.count where bytes[i + j] != binMagic[j] { continue outer2 }
                plistStart = i
                break
            }
        }
        guard let start = plistStart else { throw Error.parseFailed }
        let plistData = data[start...]
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(from: Data(plistData),
                                                                      options: [],
                                                                      format: &format) as? [String: Any] else {
            throw Error.parseFailed
        }
        guard let name = plist["Name"] as? String,
              let teams = plist["TeamIdentifier"] as? [String], let team = teams.first,
              let expiration = plist["ExpirationDate"] as? Date,
              let entitlements = plist["Entitlements"] as? [String: Any],
              let appID = entitlements["application-identifier"] as? String else {
            throw Error.missingFields
        }
        return ProvisioningProfile(
            fileName: fileName,
            name: name,
            teamIdentifier: team,
            teamName: plist["TeamName"] as? String ?? team,
            expiration: expiration,
            applicationIdentifier: appID,
            entitlements: entitlements,
            provisionedDevices: plist["ProvisionedDevices"] as? [String] ?? []
        )
    }

    /// Bundle ID covered by this profile's application identifier?
    func covers(bundleID: String) -> Bool {
        let pattern = applicationIdentifier
        if pattern.hasSuffix(".*") {
            return true  // wildcard covers everything for this team
        }
        // Explicit: TEAMID.com.example.app
        let parts = pattern.split(separator: ".", maxSplits: 1)
        guard parts.count == 2 else { return false }
        return String(parts[1]) == bundleID
    }

    /// Entitlements to embed, with identifiers mapped to this profile.
    func entitlements(for bundleID: String) -> [String: Any] {
        var out = entitlements
        let fullAppID: String
        if applicationIdentifier.hasSuffix(".*") {
            fullAppID = "\(teamIdentifier).\(bundleID)"
        } else {
            fullAppID = applicationIdentifier
        }
        out["application-identifier"] = fullAppID
        out["com.apple.developer.team-identifier"] = teamIdentifier
        // Remap keychain groups into this profile's namespace.
        if let groups = out["keychain-access-groups"] as? [String] {
            out["keychain-access-groups"] = groups.map { _ in fullAppID }
        }
        return out
    }
}
