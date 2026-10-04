import Foundation

/// Minimal DER encoder for building CMS SignedData blobs.
/// All integers are big-endian, lengths use DER short/long form.
enum DER {

    static func length(_ n: Int) -> [UInt8] {
        if n < 128 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func tlv(tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    static func sequence(_ parts: [UInt8]...) -> [UInt8] { sequence(parts.flatMap { $0 }) }
    static func sequence(_ content: [UInt8]) -> [UInt8] { tlv(tag: 0x30, content) }
    static func set(_ content: [UInt8]) -> [UInt8] { tlv(tag: 0x31, content) }

    /// INTEGER from raw big-endian bytes; prepends 0x00 if high bit set.
    static func integer(_ bytes: [UInt8]) -> [UInt8] {
        var b = bytes
        while b.count > 1 && b[0] == 0x00 { b.removeFirst() }
        if b[0] & 0x80 != 0 { b.insert(0x00, at: 0) }
        return tlv(tag: 0x02, b)
    }

    static func integer(_ value: Int) -> [UInt8] {
        var v = value, b: [UInt8] = []
        repeat { b.insert(UInt8(v & 0xFF), at: 0); v >>= 8 } while v > 0
        return integer(b)
    }

    static func octetString(_ bytes: [UInt8]) -> [UInt8] { tlv(tag: 0x04, bytes) }

    /// OID from already-encoded body bytes.
    static func oid(_ body: [UInt8]) -> [UInt8] { tlv(tag: 0x06, body) }

    static func null() -> [UInt8] { [0x05, 0x00] }

    static func utcTime(_ s: String) -> [UInt8] { tlv(tag: 0x17, Array(s.utf8)) }

    /// [n] EXPLICIT constructed.
    static func explicit(_ n: UInt8, _ content: [UInt8]) -> [UInt8] {
        tlv(tag: 0xA0 | n, content)
    }

    /// [n] IMPLICIT primitive-constructed wrapper (used for CMS [0] fields).
    static func implicit(_ n: UInt8, _ content: [UInt8]) -> [UInt8] {
        tlv(tag: 0xA0 | n, content)
    }

    // MARK: - Tiny DER reader (for X.509 parsing)

    struct TLV {
        let tag: UInt8
        let content: [UInt8]
        let totalLength: Int  // header + content
    }

    /// Parse one TLV at the start of `bytes`. Returns nil on malformed input.
    static func readTLV(_ bytes: [UInt8]) -> TLV? {
        guard bytes.count >= 2 else { return nil }
        let tag = bytes[0]
        var pos = 1
        let firstLen = bytes[pos]; pos += 1
        var len: Int
        if firstLen & 0x80 == 0 {
            len = Int(firstLen)
        } else {
            let n = Int(firstLen & 0x7F)
            guard n >= 1 && n <= 4 && bytes.count >= pos + n else { return nil }
            len = 0
            for i in 0..<n { len = (len << 8) | Int(bytes[pos + i]) }
            pos += n
        }
        guard bytes.count >= pos + len else { return nil }
        return TLV(tag: tag, content: Array(bytes[pos..<pos+len]), totalLength: pos + len)
    }

    /// Children of a constructed value.
    static func children(of tlv: TLV) -> [TLV] {
        var out: [TLV] = []
        var rest = tlv.content
        while let c = readTLV(rest) {
            out.append(c)
            rest = Array(rest.dropFirst(c.totalLength))
        }
        return out
    }
}
