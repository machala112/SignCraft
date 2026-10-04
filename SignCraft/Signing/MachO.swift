import Foundation

/// Minimal Mach-O / fat-binary parser: locates the LC_CODE_SIGNATURE command
/// and the __LINKEDIT segment in each architecture slice.
enum MachO {

    static let FAT_MAGIC:  UInt32 = 0xcafebabe
    static let MH_MAGIC:    UInt32 = 0xfeedface
    static let MH_MAGIC_64: UInt32 = 0xfeedfacf
    static let LC_SEGMENT:    UInt32 = 0x1
    static let LC_SEGMENT_64: UInt32 = 0x19
    static let LC_CODE_SIGNATURE: UInt32 = 0x1d

    enum Error: Swift.Error, LocalizedError {
        case notMachO
        case truncated
        case noCodeSignature
        var errorDescription: String? {
            switch self {
            case .notMachO: return "Not a Mach-O binary"
            case .truncated: return "Truncated Mach-O binary"
            case .noCodeSignature: return "Binary has no LC_CODE_SIGNATURE slot (cannot re-sign)"
            }
        }
    }

    struct Slice {
        /// Offset of this slice within the file.
        let fileOffset: Int
        /// Size of this slice within the file.
        let fileSize: Int
        /// Offset of the mach header relative to slice start.
        let headerOffset: Int
        let is64: Bool
        let isFat: Bool
        /// Fat arch index (for rebuilding), nil for thin binaries.
        let fatIndex: Int?
    }

    struct SignatureSlot {
        /// File offset of the LC_CODE_SIGNATURE command itself.
        let commandOffset: Int
        /// Offset of signature data, relative to slice start.
        var dataOffset: Int
        /// Size of signature data.
        var dataSize: Int
    }

    struct LinkEdit {
        /// File offset of the LC_SEGMENT_64 command.
        let commandOffset: Int
        /// Offset of filesize field within the command.
        let filesizeFieldOffset: Int
        /// fileoff of __LINKEDIT (relative to slice start).
        let fileOff: Int
        var fileSize: Int
    }

    // MARK: - Reading helpers (little-endian; fat headers are big-endian)

    static func u32le(_ d: [UInt8], _ o: Int) -> UInt32 {
        UInt32(d[o]) | UInt32(d[o+1]) << 8 | UInt32(d[o+2]) << 16 | UInt32(d[o+3]) << 24
    }
    static func u32be(_ d: [UInt8], _ o: Int) -> UInt32 {
        UInt32(d[o]) << 24 | UInt32(d[o+1]) << 16 | UInt32(d[o+2]) << 8 | UInt32(d[o+3])
    }
    static func u64le(_ d: [UInt8], _ o: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(d[o+i]) << (8*i) }
        return v
    }
    static func putU32le(_ d: inout [UInt8], _ o: Int, _ v: UInt32) {
        d[o] = UInt8(v & 0xFF); d[o+1] = UInt8((v >> 8) & 0xFF)
        d[o+2] = UInt8((v >> 16) & 0xFF); d[o+3] = UInt8((v >> 24) & 0xFF)
    }
    static func putU64le(_ d: inout [UInt8], _ o: Int, _ v: UInt64) {
        for i in 0..<8 { d[o+i] = UInt8((v >> (8*i)) & 0xFF) }
    }

    static func isMachO(_ data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let b = [UInt8](data.prefix(4))
        let le = u32le(b, 0)
        return le == MH_MAGIC || le == MH_MAGIC_64 || le == FAT_MAGIC || u32be(b, 0) == FAT_MAGIC
    }

    /// Split file data into architecture slices.
    static func slices(of fileData: [UInt8]) throws -> [Slice] {
        guard fileData.count >= 4 else { throw Error.truncated }
        let magic = u32le(fileData, 0)
        if magic == FAT_MAGIC {
            let nfat = Int(u32be(fileData, 4))
            var out: [Slice] = []
            for i in 0..<nfat {
                let base = 8 + i * 20
                guard fileData.count >= base + 20 else { throw Error.truncated }
                let offset = Int(u32be(fileData, base + 8))
                let size = Int(u32be(fileData, base + 12))
                let align = Int(u32be(fileData, base + 16))
                guard fileData.count >= offset + size else { throw Error.truncated }
                let hm = u32le(fileData, offset)
                let is64 = (hm == MH_MAGIC_64)
                guard hm == MH_MAGIC || is64 else { throw Error.notMachO }
                out.append(Slice(fileOffset: offset, fileSize: size, headerOffset: 0,
                                 is64: is64, isFat: true, fatIndex: i))
                _ = align
            }
            return out
        } else if magic == MH_MAGIC || magic == MH_MAGIC_64 {
            return [Slice(fileOffset: 0, fileSize: fileData.count, headerOffset: 0,
                          is64: magic == MH_MAGIC_64, isFat: false, fatIndex: nil)]
        }
        throw Error.notMachO
    }

    /// Find the code-signature slot and __LINKEDIT in one slice.
    /// Offsets returned are relative to the slice start.
    static func signatureSlotAndLinkEdit(sliceData: [UInt8], is64: Bool) throws -> (SignatureSlot, LinkEdit) {
        let headerSize = is64 ? 32 : 28
        guard sliceData.count >= headerSize else { throw Error.truncated }
        let ncmds = Int(u32le(sliceData, 16))
        var off = headerSize
        var sig: SignatureSlot?
        var link: LinkEdit?
        for _ in 0..<ncmds {
            guard sliceData.count >= off + 8 else { throw Error.truncated }
            let cmd = u32le(sliceData, off)
            let cmdsize = Int(u32le(sliceData, off + 4))
            guard cmdsize >= 8 && sliceData.count >= off + cmdsize else { throw Error.truncated }
            if cmd == LC_CODE_SIGNATURE {
                sig = SignatureSlot(commandOffset: off,
                                    dataOffset: Int(u32le(sliceData, off + 8)),
                                    dataSize: Int(u32le(sliceData, off + 12)))
            } else if cmd == LC_SEGMENT_64 && is64 {
                let nameBytes = Array(sliceData[(off+8)..<(off+24)])
                let name = String(bytes: nameBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
                if name == "__LINKEDIT" {
                    link = LinkEdit(commandOffset: off,
                                    filesizeFieldOffset: off + 48,
                                    fileOff: Int(u64le(sliceData, off + 40)),
                                    fileSize: Int(u64le(sliceData, off + 48)))
                }
            } else if cmd == LC_SEGMENT && !is64 {
                let nameBytes = Array(sliceData[(off+8)..<(off+24)])
                let name = String(bytes: nameBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
                if name == "__LINKEDIT" {
                    link = LinkEdit(commandOffset: off,
                                    filesizeFieldOffset: off + 36,
                                    fileOff: Int(u32le(sliceData, off + 32)),
                                    fileSize: Int(u32le(sliceData, off + 36)))
                }
            }
            off += cmdsize
        }
        guard let s = sig else { throw Error.noCodeSignature }
        guard let l = link else { throw Error.truncated }
        return (s, l)
    }

    /// Rebuild a fat binary from resigned slices (each already containing its
    /// new signature appended). Slice order is preserved; offsets 4K-aligned.
    static func rebuildFat(original: [UInt8], newSlices: [[UInt8]]) throws -> [UInt8] {
        let nfat = Int(u32be(original, 4))
        precondition(newSlices.count == nfat)
        let headerSize = 8 + nfat * 20
        var out: [UInt8] = []
        out.reserveCapacity(headerSize + newSlices.reduce(0) { $0 + $1.count } + 4096 * nfat)
        // header (patched later)
        out += [UInt8](repeating: 0, count: headerSize)
        var archEntries: [(offset: Int, size: Int)] = []
        var pos = headerSize
        for slice in newSlices {
            // 4K align
            let aligned = (pos + 4095) & ~4095
            if aligned > pos { out += [UInt8](repeating: 0, count: aligned - pos) }
            pos = aligned
            archEntries.append((offset: pos, size: slice.count))
            out += slice
            pos += slice.count
        }
        // write fat_header + fat_arch (big-endian)
        func put32be(_ o: Int, _ v: UInt32) {
            out[o] = UInt8((v >> 24) & 0xFF); out[o+1] = UInt8((v >> 16) & 0xFF)
            out[o+2] = UInt8((v >> 8) & 0xFF); out[o+3] = UInt8(v & 0xFF)
        }
        put32be(0, FAT_MAGIC); put32be(4, UInt32(nfat))
        for i in 0..<nfat {
            let base = 8 + i * 20
            // copy cputype/cpusubtype from original
            for j in 0..<8 { out[base + j] = original[base + j] }
            put32be(base + 8, UInt32(archEntries[i].offset))
            put32be(base + 12, UInt32(archEntries[i].size))
            put32be(base + 16, 12)  // align = 2^12
        }
        return out
    }
}
