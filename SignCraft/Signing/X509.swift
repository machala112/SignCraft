import Foundation

/// Minimal X.509 parser: extracts the issuer Name (raw DER) and serial number
/// bytes needed for the CMS SignerInfo. The actual RSA operation is done via
/// the Security framework, so no public-key parsing is required here.
struct X509Certificate {
    /// Full DER of the issuer Name field (TLV, tag included).
    let issuerDER: [UInt8]
    /// Raw big-endian serial number bytes.
    let serialBytes: [UInt8]

    static func parse(_ der: Data) -> X509Certificate? {
        let bytes = [UInt8](der)
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        guard let cert = DER.readTLV(bytes), cert.tag == 0x30 else { return nil }
        let certChildren = DER.children(of: cert)
        guard certChildren.count >= 1 else { return nil }
        // tbsCertificate ::= SEQUENCE { [0] EXPLICIT version, serial INTEGER, ... }
        let tbs = certChildren[0]
        guard tbs.tag == 0x30 else { return nil }
        let tbsChildren = DER.children(of: tbs)
        // tbsCertificate ::= SEQUENCE {
        //   [0] EXPLICIT version (optional, absent in v1 certs),
        //   serialNumber INTEGER, signature, issuer Name, ... }
        let hasVersion = tbsChildren.first?.tag == 0xA0
        let serialIdx = hasVersion ? 1 : 0
        let issuerIdx = hasVersion ? 3 : 2
        guard tbsChildren.count > issuerIdx else { return nil }
        let serialTLV = tbsChildren[serialIdx]
        let issuerTLV = tbsChildren[issuerIdx]
        guard serialTLV.tag == 0x02, issuerTLV.tag == 0x30 else { return nil }
        // Re-encode issuer TLV (tag + length + content)
        let issuerDER = [issuerTLV.tag] + DER.length(issuerTLV.content.count) + issuerTLV.content
        return X509Certificate(issuerDER: issuerDER, serialBytes: serialTLV.content)
    }
}
