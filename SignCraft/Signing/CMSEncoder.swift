import Foundation
import CryptoKit

/// Builds a CMS SignedData blob (DER) signing a CodeDirectory, mirroring what
/// Apple's codesign produces. The RSA signature itself is computed with the
/// Security framework; everything else is hand-encoded ASN.1.
///
/// IMPORTANT: the signedAttrs bytes are generated once and reused for both
/// hashing/signing and embedding, so the signature always matches.
enum CMSEncoder {

    // Pre-encoded OID bodies
    private static let oidSignedData: [UInt8]       = [0x2A,0x86,0x48,0x86,0xF7,0x12,0x01,0x07,0x02]
    private static let oidData: [UInt8]              = [0x2A,0x86,0x48,0x86,0xF7,0x12,0x01,0x07,0x01]
    private static let oidSHA256: [UInt8]           = [0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01]
    private static let oidSHA256WithRSA: [UInt8]    = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B]
    private static let oidContentType: [UInt8]       = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x03]
    private static let oidMessageDigest: [UInt8]     = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04]
    private static let oidSigningTime: [UInt8]       = [0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x05]

    private static func algorithmIdentifier(oid: [UInt8]) -> [UInt8] {
        DER.sequence(DER.oid(oid) + DER.null())
    }

    private static func attribute(oid: [UInt8], value: [UInt8]) -> [UInt8] {
        DER.sequence(DER.oid(oid) + DER.set(value))
    }

    private static func utcTimeNow() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyMMddHHmmss'Z'"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: Date())
    }

    /// The [0] IMPLICIT SignedAttributes bytes. Generate ONCE per signature.
    static func buildSignedAttrs(codeDirectory: [UInt8]) -> [UInt8] {
        let cdHash = [UInt8](SHA256.hash(data: codeDirectory))
        // DER SET OF ordering: attributes sorted by OID encoding
        // (contentType < messageDigest < signingTime).
        let attrs =
            attribute(oid: oidContentType, value: DER.oid(oidData)) +
            attribute(oid: oidMessageDigest, value: DER.octetString(cdHash)) +
            attribute(oid: oidSigningTime, value: DER.utcTime(utcTimeNow()))
        return DER.implicit(0, DER.set(attrs))
    }

    /// Build the full CMS ContentInfo DER.
    /// - Parameters:
    ///   - signedAttrs: bytes from `buildSignedAttrs` (the exact bytes that were signed)
    ///   - signer: parsed leaf certificate (issuer + serial for SignerInfo)
    ///   - chainDER: certificate chain, leaf first (raw DER each)
    ///   - signature: RSA signature over `signedAttrs`
    static func signedData(signedAttrs: [UInt8],
                           signer: X509Certificate,
                           chainDER: [Data],
                           signature: [UInt8]) -> [UInt8] {
        let signerInfo = DER.sequence(
            DER.integer(1) +
            DER.sequence(
                signer.issuerDER +
                DER.integer(signer.serialBytes)
            ) +
            algorithmIdentifier(oid: oidSHA256) +
            signedAttrs +
            algorithmIdentifier(oid: oidSHA256WithRSA) +
            DER.octetString(signature)
        )

        var certsBytes: [UInt8] = []
        for c in chainDER { certsBytes += [UInt8](c) }

        let signedData = DER.sequence(
            DER.integer(1) +
            DER.set(algorithmIdentifier(oid: oidSHA256)) +
            DER.sequence(DER.oid(oidData)) +                       // encapContentInfo (detached)
            DER.implicit(0, certsBytes) +                          // certificates [0]
            DER.set(signerInfo)                                   // signerInfos
        )

        return DER.sequence(
            DER.oid(oidSignedData) +
            DER.explicit(0, signedData)
        )
    }
}
