import SwiftUI
import UIKit

/// Pick certificate + profile, sign, then install.
struct SignFlowView: View {
    @EnvironmentObject var store: AppStore
    @Environment(\.dismiss) var dismiss
    let ipa: IPAFile

    @State private var certID: UUID?
    @State private var profileID: UUID?
    @State private var signing = false
    @State private var progress: Double = 0
    @State private var status = ""
    @State private var error: String?
    @State private var signedURL: URL?
    @State private var installURL: URL?
    @StateObject private var installer = Installer()

    var canSign: Bool { certID != nil && profileID != nil && !signing && signedURL == nil }

    var body: some View {
        NavigationStack {
            Form {
                Section("App") {
                    Text(ipa.fileName).lineLimit(1)
                    Text(ipa.displaySize).font(.caption).foregroundColor(.secondary)
                }
                Section("Certificate") {
                    if store.certificates.isEmpty {
                        Text("Import a .p12 in the Certificates tab first.")
                            .foregroundColor(.secondary)
                    } else {
                        Picker("Certificate", selection: $certID) {
                            Text("Select…").tag(nil as UUID?)
                            ForEach(store.certificates) { c in
                                Text(c.label).tag(c.id as UUID?)
                            }
                        }
                    }
                }
                Section("Provisioning profile") {
                    if store.profiles.isEmpty {
                        Text("Import a .mobileprovision in the Certificates tab first.")
                            .foregroundColor(.secondary)
                    } else {
                        Picker("Profile", selection: $profileID) {
                            Text("Select…").tag(nil as UUID?)
                            ForEach(store.profiles) { p in
                                Text(p.profile.name).tag(p.id as UUID?)
                            }
                        }
                    }
                }
                if signing || progress > 0 {
                    Section("Progress") {
                        ProgressView(value: progress)
                        Text(status).font(.caption).foregroundColor(.secondary)
                    }
                }
                if let error {
                    Section { Text(error).foregroundColor(.red).font(.callout) }
                }
                if signedURL != nil {
                    Section {
                        Button("Install app") {
                            guard let url = installURL else { return }
                            UIApplication.shared.open(url)
                        }
                        .font(.headline)
                        Text("iOS will ask you to confirm the install. Keep SignCraft open until it finishes.")
                            .font(.caption).foregroundColor(.secondary)
                    }
                } else {
                    Section {
                        Button(signing ? "Signing…" : "Sign app") { startSigning() }
                            .disabled(!canSign)
                    }
                }
            }
            .navigationTitle("Sign & Install")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button("Close") { installer.finish(); dismiss() }
            }
        }
    }

    private func startSigning() {
        guard let cert = store.certificates.first(where: { $0.id == certID }),
              let item = store.profiles.first(where: { $0.id == profileID }) else { return }
        signing = true
        error = nil
        progress = 0
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let identity = try store.identity(for: cert)
                let out = try Signer.sign(ipaURL: ipa.localURL,
                                          identity: identity,
                                          profile: item.profile,
                                          profileFileURL: item.localURL) { p, s in
                    DispatchQueue.main.async { progress = p; status = s }
                }
                // Read bundle metadata for the manifest.
                let (bundleID, version, name) = appMetadata(of: out) ?? ("app", "1.0", ipa.fileName)
                let itms = try installer.prepareInstall(ipaURL: out, bundleID: bundleID,
                                                        version: version, name: name)
                DispatchQueue.main.async {
                    signedURL = out
                    installURL = itms
                    signing = false
                    status = "Signed — tap Install."
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = error.localizedDescription
                    signing = false
                }
            }
        }
    }

    /// Read bundle ID / version / name from a signed IPA.
    private func appMetadata(of ipaURL: URL) -> (String, String, String)? {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("meta-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tmp) }
            try FileManager.default.unzipItem(at: ipaURL, to: tmp)
            guard let appDir = Signer.findAppDirectory(in: tmp),
                  let data = try? Data(contentsOf: appDir.appendingPathComponent("Info.plist")),
                  let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let bid = info["CFBundleIdentifier"] as? String else { return nil }
            let ver = info["CFBundleShortVersionString"] as? String ?? "1.0"
            let name = (info["CFBundleDisplayName"] as? String)
                ?? (info["CFBundleName"] as? String) ?? "App"
            return (bid, ver, name)
        } catch { return nil }
    }
}
