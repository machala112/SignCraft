import Foundation
import CryptoKit

/// Re-signs an IPA with a SigningIdentity + ProvisioningProfile, on-device.
/// Mirrors what ESign does: swap the provisioning profile, re-sign every
/// Mach-O with a real CMS signature, re-package. Sealed resources are never
/// touched (embedded.mobileprovision is excluded from resource sealing), so
/// _CodeSignature/CodeResources stays valid.
enum Signer {

    enum Error: Swift.Error, LocalizedError {
        case badIPA(String)
        case bundleIDMismatch(String)
        case profileExpired
        case noBinaries
        var errorDescription: String? {
            switch self {
            case .badIPA(let m): return "Bad IPA: \(m)"
            case .bundleIDMismatch(let m): return "Bundle ID problem: \(m)"
            case .profileExpired: return "Provisioning profile has expired"
            case .noBinaries: return "No signed binaries found in IPA"
            }
        }
    }

    // MARK: - Public entry point

    /// - Returns: file URL of the newly signed IPA (in a temp directory).
    static func sign(ipaURL: URL,
                     identity: SigningIdentity,
                     profile: ProvisioningProfile,
                     profileFileURL: URL,
                     progress: @escaping (Double, String) -> Void) throws -> URL {
        if profile.isExpired { throw Error.profileExpired }
        progress(0.02, "Unpacking IPA…")
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("signcraft-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer { /* keep for debugging; cleaned on next run */ }
        try FileManager.default.unzipItem(at: ipaURL, to: workDir)

        guard let appDir = findAppDirectory(in: workDir) else {
            throw Error.badIPA("no .app bundle inside Payload/")
        }
        let infoURL = appDir.appendingPathComponent("Info.plist")
        guard let infoData = try? Data(contentsOf: infoURL),
              let info = try? PropertyListSerialization.propertyList(from: infoData, format: nil) as? [String: Any],
              let bundleID = info["CFBundleIdentifier"] as? String else {
            throw Error.badIPA("cannot read Info.plist")
        }
        progress(0.08, "App: \(bundleID)")

        guard profile.covers(bundleID: bundleID) else {
            throw Error.bundleIDMismatch(
                "'\(bundleID)' is not covered by profile '\(profile.name)' (\(profile.applicationIdentifier)). " +
                "Use a wildcard profile or rename the bundle ID.")
        }

        // Swap provisioning profile (not part of sealed resources — safe).
        progress(0.12, "Installing provisioning profile…")
        let profileDest = appDir.appendingPathComponent("embedded.mobileprovision")
        if FileManager.default.fileExists(atPath: profileDest.path) {
            try FileManager.default.removeItem(at: profileDest)
        }
        try FileManager.default.copyItem(at: profileFileURL, to: profileDest)

        // Entitlements for this app.
        let entitlements = profile.entitlements(for: bundleID)
        let entData = try PropertyListSerialization.data(fromPropertyList: entitlements,
                                                         format: .xml, options: 0)

        // Find every Mach-O binary.
        let binaries = machOBinaries(in: appDir, info: info)
        guard !binaries.isEmpty else { throw Error.noBinaries }
        progress(0.18, "Signing \(binaries.count) binaries…")

        for (i, binURL) in binaries.enumerated() {
            progress(0.18 + 0.62 * Double(i) / Double(binaries.count),
                     "Signing \(binURL.lastPathComponent)…")
            var fileBytes = [UInt8](try Data(contentsOf: binURL))
            guard MachO.isMachO(Data(fileBytes)) else { continue }
            let slices = try MachO.slices(of: fileBytes)
            var newSlices: [[UInt8]] = []
            for slice in slices {
                let sliceBytes = Array(fileBytes[slice.fileOffset..<(slice.fileOffset + slice.fileSize)])
                newSlices.append(try signSlice(sliceBytes, is64: slice.is64,
                                               identity: identity,
                                               identifier: bundleID,
                                               teamID: profile.teamIdentifier,
                                               entitlements: entData))
            }
            if slices.count == 1 && !slices[0].isFat {
                fileBytes = newSlices[0]
            } else {
                fileBytes = try MachO.rebuildFat(original: fileBytes, newSlices: newSlices)
            }
            try Data(fileBytes).write(to: binURL)
        }

        // Re-package.
        progress(0.85, "Re-packaging IPA…")
        let outURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(bundleID)-signed.ipa")
        if FileManager.default.fileExists(atPath: outURL.path) {
            try FileManager.default.removeItem(at: outURL)
        }
        guard let archive = Archive(url: outURL, accessMode: .create) else {
            throw Error.badIPA("cannot create output IPA")
        }
        let payloadDir = workDir.appendingPathComponent("Payload")
        let enumerator = FileManager.default.enumerator(at: payloadDir,
                                                        includingPropertiesForKeys: [.isDirectoryKey])
        while let fileURL = enumerator?.nextObject() as? URL {
            let values = try fileURL.resourceValues(forKeys: [.isDirectoryKey])
            if values.isDirectory == true { continue }
            let rel = "Payload/" + fileURL.path.replacingOccurrences(of: payloadDir.path + "/", with: "")
            try archive.addEntry(with: rel, relativeTo: workDir, compressionMethod: .deflate)
        }
        try? FileManager.default.removeItem(at: workDir)
        progress(1.0, "Done")
        return outURL
    }

    // MARK: - Binary discovery

    static func findAppDirectory(in workDir: URL) -> URL? {
        let payload = workDir.appendingPathComponent("Payload")
        let items = (try? FileManager.default.contentsOfDirectory(at: payload,
                                                                  includingPropertiesForKeys: nil)) ?? []
        return items.first(where: { $0.pathExtension == "app" })
    }

    static func machOBinaries(in appDir: URL, info: [String: Any]) -> [URL] {
        var urls: [URL] = []
        let fm = FileManager.default
        if let exe = info["CFBundleExecutable"] as? String {
            let main = appDir.appendingPathComponent(exe)
            if fm.fileExists(atPath: main.path) { urls.append(main) }
        }
        for sub in ["Frameworks", "PlugIns"] {
            let dir = appDir.appendingPathComponent(sub)
            guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else { continue }
            for item in items {
                if item.pathExtension == "framework" || item.pathExtension == "appex" {
                    let name = item.deletingPathExtension().lastPathComponent
                    let bin = item.appendingPathComponent(name)
                    if fm.fileExists(atPath: bin.path) { urls.append(bin) }
                } else if item.pathExtension == "dylib" {
                    urls.append(item)
                }
            }
        }
        return urls
    }

    // MARK: - Per-slice signing (two passes)

    /// Re-sign one thin slice. New signature is appended at the end of the
    /// slice; __LINKEDIT is grown to cover it; fat headers are fixed by the caller.
    static func signSlice(_ slice: [UInt8],
                          is64: Bool,
                          identity: SigningIdentity,
                          identifier: String,
                          teamID: String,
                          entitlements: Data) throws -> [UInt8] {
        var working = slice
        let (slot, link) = try MachO.signatureSlotAndLinkEdit(sliceData: working, is64: is64)

        let entBlob = CodeSignature.entitlementsBlob(plist: entitlements)
        let reqBlob = CodeSignature.emptyRequirements()
        let zeroHash = [UInt8](repeating: 0, count: CodeSignature.HASH_SIZE)
        // Special slots, index 0 = slot 5 (entitlements), descending.
        let special: [[UInt8]] = [
            CodeSignature.sha256(entBlob),  // slot 5
            zeroHash,                        // slot 4
            zeroHash,                        // slot 3
            CodeSignature.sha256(reqBlob),   // slot 2
            zeroHash,                        // slot 1
        ]

        // Layout: new signature appended at end of slice.
        let newSigOffset = working.count
        let newCodeLimit = newSigOffset

        // Zero the old signature bytes (they fall inside the hashed region).
        for i in slot.dataOffset..<(slot.dataOffset + slot.dataSize) {
            if i < working.count { working[i] = 0 }
        }
        // Point LC_CODE_SIGNATURE at the new location (datasize filled in pass 2).
        MachO.putU32le(&working, slot.commandOffset + 8, UInt32(newSigOffset))
        MachO.putU32le(&working, slot.commandOffset + 12, 0)

        func buildSuperBlob() throws -> [UInt8] {
            let pageHashes = CodeSignature.hashPages(of: working, codeLimit: newCodeLimit)
            let cd = CodeSignature.codeDirectory(pageHashes: pageHashes,
                                                 specialHashes: special,
                                                 identifier: identifier,
                                                 teamID: teamID,
                                                 codeLimit: newCodeLimit)
            let attrs = CMSEncoder.buildSignedAttrs(codeDirectory: cd)
            let digest = [UInt8](SHA256.hash(data: attrs))
            let sig = try identity.signDigest(digest)
            let cms = CMSEncoder.signedData(signedAttrs: attrs,
                                            signer: identity.leafCertificate,
                                            chainDER: identity.chainDER,
                                            signature: sig)
            return CodeSignature.superBlob(codeDirectory: cd,
                                           requirements: reqBlob,
                                           entitlements: entBlob,
                                           cms: CodeSignature.cmsWrapper(cms: cms))
        }

        // Pass 1: discover the signature size.
        let pass1 = try buildSuperBlob()
        let sigSize = pass1.count

        // Pass 2: write the real header values (only page 0 changes),
        // then rebuild with the corrected page-0 hash. Blob size is
        // deterministic, so no further iteration is needed.
        MachO.putU32le(&working, slot.commandOffset + 12, UInt32(sigSize))
        let newEnd = newSigOffset + sigSize
        if is64 {
            MachO.putU64le(&working, link.filesizeFieldOffset, UInt64(newEnd - link.fileOff))
        } else {
            MachO.putU32le(&working, link.filesizeFieldOffset, UInt32(newEnd - link.fileOff))
        }
        let pass2 = try buildSuperBlob()
        precondition(pass2.count == sigSize, "signature size must be stable across passes")

        working += pass2
        return working
    }
}
