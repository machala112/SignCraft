import Foundation
import Security

/// A code-signing identity imported from a .p12 file.
struct SigningIdentity: Identifiable {
    let id = UUID()
    let label: String
    let privateKey: SecKey
    /// DER-encoded certificates, leaf first.
    let chainDER: [Data]
    let leafCertificate: X509Certificate
    let importedAt: Date

    enum Error: Swift.Error, LocalizedError {
        case importFailed(String)
        case noIdentity
        case certParseFailed
        var errorDescription: String? {
            switch self {
            case .importFailed(let m): return "Could not import .p12: \(m)"
            case .noIdentity: return "No identity found in .p12"
            case .certParseFailed: return "Could not parse signing certificate"
            }
        }
    }

    static func importP12(_ data: Data, password: String, label: String) throws -> SigningIdentity {
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: password] as CFDictionary
        let status = SecPKCS12Import(data as CFData, options, &items)
        guard status == errSecSuccess, let arr = items as? [[String: Any]], !arr.isEmpty else {
            throw Error.importFailed("wrong password or corrupt file (OSStatus \(status))")
        }
        let dict = arr[0]
        guard let rawIdentity = dict[kSecImportItemIdentity as String],
              let chain = dict[kSecImportItemCertChain as String] as? [SecCertificate],
              !chain.isEmpty else {
            throw Error.noIdentity
        }
        let identity = rawIdentity as! SecIdentity
        var privKey: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &privKey) == errSecSuccess, let key = privKey else {
            throw Error.noIdentity
        }
        let chainDER = chain.map { SecCertificateCopyData($0) as Data }
        guard let leaf = X509Certificate.parse(chainDER[0]) else { throw Error.certParseFailed }
        return SigningIdentity(label: label, privateKey: key, chainDER: chainDER,
                               leafCertificate: leaf, importedAt: Date())
    }

    /// RSA PKCS#1 v1.5 signature over a pre-hashed digest (SHA-256).
    func signDigest(_ digest: [UInt8]) throws -> [UInt8] {
        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(privateKey,
                                              .rsaSignatureDigestPKCS1v15SHA256,
                                              Data(digest) as CFData, &err) else {
            throw CodeSignature.Error.signingFailed(err?.takeRetainedValue().localizedDescription ?? "unknown")
        }
        return [UInt8](sig as Data)
    }
}
