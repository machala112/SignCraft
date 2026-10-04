import Foundation
import CryptoKit

/// Builds Apple code signatures: CodeDirectory + SuperBlob, and re-signs
/// individual Mach-O slices. Big-endian throughout (Apple's signature format).
enum CodeSignature {

    // Blob magics
    static let CS_SUPERBLOB:       UInt32 = 0xfade0cc0
    static let CS_CODEDIRECTORY:    UInt32 = 0xfade0c02
    static let CS_REQUIREMENTS:     UInt32 = 0xfade0c01
    static let CS_ENTITLEMENTS:     UInt32 = 0xfade7171
    static let CS_CMSBLOB:          UInt32 = 0xfade0b01

    // Slot numbers
    static let SLOT_CODEDIRECTORY: UInt32 = 0
    static let SLOT_REQUIREMENTS:  UInt32 = 2
    static let SLOT_ENTITLEMENTS:  UInt32 = 5
    static let SLOT_SIGNATURE:     UInt32 = 0x10000

    static let PAGE_SIZE_LOG2: UInt8 = 12          // 4096
    static let PAGE_SIZE = 4096
    static let HASH_SIZE = 32                       // SHA-256
    static let N_SPECIAL_SLOTS = 5

    enum Error: Swift.Error, LocalizedError {
        case signingFailed(String)
        var errorDescription: String? {
            switch self { case .signingFailed(let m): return "Signing failed: \(m)" }
        }
    }

    // MARK: - Big-endian writers

    static func put32(_ v: UInt32, into out: inout [UInt8]) {
        out.append(UInt8((v >> 24) & 0xFF)); out.append(UInt8((v >> 16) & 0xFF))
        out.append(UInt8((v >> 8) & 0xFF));  out.append(UInt8(v & 0xFF))
    }
    static func put64(_ v: UInt64, into out: inout [UInt8]) {
        for i in (0..<8).reversed() { out.append(UInt8((v >> (8 * i)) & 0xFF)) }
    }
    static func putBytes(_ b: [UInt8], into out: inout [UInt8]) { out += b }

    // MARK: - Blobs

    /// Empty requirements blob (valid; used by on-device signers).
    static func emptyRequirements() -> [UInt8] {
        var out: [UInt8] = []
        put32(CS_REQUIREMENTS, into: &out)
        put32(8, into: &out)
        return out
    }

    static func entitlementsBlob(plist: Data) -> [UInt8] {
        var out: [UInt8] = []
        put32(CS_ENTITLEMENTS, into: &out)
        put32(UInt32(8 + plist.count), into: &out)
        putBytes([UInt8](plist), into: &out)
        return out
    }

    /// CodeDirectory blob. `specialHashes[i]` corresponds to special slot
    /// (N_SPECIAL_SLOTS - i), i.e. index 0 = slot 5 (entitlements).
    static func codeDirectory(pageHashes: [[UInt8]],
                              specialHashes: [[UInt8]],
                              identifier: String,
                              teamID: String?,
                              codeLimit: Int) -> [UInt8] {
        precondition(specialHashes.count == N_SPECIAL_SLOTS)
        let identBytes = Array(identifier.utf8) + [0]
        let teamBytes: [UInt8] = teamID.map { Array($0.utf8) + [UInt8(0)] } ?? []

        let headerSize = 0x40
        let identOffset = headerSize
        var hashOffset = identOffset + identBytes.count
        hashOffset = (hashOffset + 3) & ~3
        let teamOffset: Int
        let totalHashes = specialHashes.count + pageHashes.count
        if teamBytes.isEmpty {
            teamOffset = 0
        } else {
            teamOffset = hashOffset + totalHashes * HASH_SIZE
        }
        var length = (teamBytes.isEmpty ? hashOffset + totalHashes * HASH_SIZE
                                        : teamOffset + teamBytes.count)
        length = (length + 3) & ~3

        var out: [UInt8] = []
        out.reserveCapacity(length)
        put32(CS_CODEDIRECTORY, into: &out)
        put32(UInt32(length), into: &out)
        put32(0x20400, into: &out)                    // version
        put32(0, into: &out)                          // flags
        put32(UInt32(hashOffset), into: &out)
        put32(UInt32(identOffset), into: &out)
        put32(UInt32(N_SPECIAL_SLOTS), into: &out)
        put32(UInt32(pageHashes.count), into: &out)
        put32(UInt32(codeLimit), into: &out)
        out.append(UInt8(HASH_SIZE))                   // hashSize
        out.append(2)                                 // hashType = SHA-256
        out.append(0)                                 // platform
        out.append(PAGE_SIZE_LOG2)                     // pageSize
        put32(0, into: &out)                          // spare2
        put32(0, into: &out)                          // scatterOffset
        put32(UInt32(teamOffset), into: &out)
        put32(0, into: &out)                          // spare3
        put64(UInt64(codeLimit), into: &out)          // codeLimit64
        // ident + padding
        putBytes(identBytes, into: &out)
        while out.count < hashOffset { out.append(0) }
        // hashes: special slots first (slot 5 at index 0), then code pages
        for h in specialHashes + pageHashes {
            precondition(h.count == HASH_SIZE)
            putBytes(h, into: &out)
        }
        if !teamBytes.isEmpty { putBytes(teamBytes, into: &out) }
        while out.count < length { out.append(0) }
        return out
    }

    static func cmsWrapper(cms: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        put32(CS_CMSBLOB, into: &out)
        put32(UInt32(8 + cms.count), into: &out)
        putBytes(cms, into: &out)
        return out
    }

    /// Assemble the SuperBlob (LC_CODE_SIGNATURE payload).
    static func superBlob(codeDirectory: [UInt8],
                          requirements: [UInt8],
                          entitlements: [UInt8],
                          cms: [UInt8]) -> [UInt8] {
        let blobs: [(UInt32, [UInt8])] = [
            (SLOT_CODEDIRECTORY, codeDirectory),
            (SLOT_REQUIREMENTS, requirements),
            (SLOT_ENTITLEMENTS, entitlements),
            (SLOT_SIGNATURE, cms),
        ]
        var out: [UInt8] = []
        put32(CS_SUPERBLOB, into: &out)
        let countOffset = out.count
        put32(0, into: &out)              // length (patched)
        put32(UInt32(blobs.count), into: &out)
        let entriesOffset = out.count
        // reserve index entries
        for _ in blobs { put32(0, into: &out); put32(0, into: &out) }
        var cursor = (out.count + 7) & ~7
        for (i, (type, blob)) in blobs.enumerated() {
            while out.count < cursor { out.append(0) }
            let entryOff = entriesOffset + i * 8
            // patch type + offset (big-endian)
            out[entryOff] = UInt8((type >> 24) & 0xFF); out[entryOff+1] = UInt8((type >> 16) & 0xFF)
            out[entryOff+2] = UInt8((type >> 8) & 0xFF); out[entryOff+3] = UInt8(type & 0xFF)
            let o = UInt32(cursor)
            out[entryOff+4] = UInt8((o >> 24) & 0xFF); out[entryOff+5] = UInt8((o >> 16) & 0xFF)
            out[entryOff+6] = UInt8((o >> 8) & 0xFF); out[entryOff+7] = UInt8(o & 0xFF)
            putBytes(blob, into: &out)
            cursor = (out.count + 7) & ~7
        }
        let len = UInt32(out.count)
        out[countOffset] = UInt8((len >> 24) & 0xFF); out[countOffset+1] = UInt8((len >> 16) & 0xFF)
        out[countOffset+2] = UInt8((len >> 8) & 0xFF); out[countOffset+3] = UInt8(len & 0xFF)
        return out
    }

    // MARK: - Page hashing

    static func hashPages(of data: [UInt8], codeLimit: Int) -> [[UInt8]] {
        var hashes: [[UInt8]] = []
        var off = 0
        while off < codeLimit {
            let end = min(off + PAGE_SIZE, codeLimit)
            hashes.append([UInt8](SHA256.hash(data: data[off..<end])))
            off = end
        }
        return hashes
    }

    static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        [UInt8](SHA256.hash(data: bytes))
    }
}
