import SwiftUI
import UniformTypeIdentifiers

struct CertificatesView: View {
    @EnvironmentObject var store: AppStore
    @State private var importingP12 = false
    @State private var importingProfile = false
    @State private var p12URL: URL?
    @State private var p12Password = ""
    @State private var p12Label = ""
    @State private var showPasswordPrompt = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                certificatesSection
                profilesSection
                if let error {
                    Section { Text(error).foregroundColor(.red).font(.caption) }
                }
            }
            .navigationTitle("Certificates")
            .fileImporter(isPresented: $importingP12,
                          allowedContentTypes: [.init(filenameExtension: "p12") ?? .data]) { result in
                handleP12Import(result)
            }
            .fileImporter(isPresented: $importingProfile,
                          allowedContentTypes: [.init(filenameExtension: "mobileprovision") ?? .data]) { result in
                handleProfileImport(result)
            }
            .alert("Certificate password", isPresented: $showPasswordPrompt) {
                TextField("Label", text: $p12Label)
                SecureField("Password", text: $p12Password)
                Button("Import") { confirmP12Import() }
                Button("Cancel", role: .cancel) { p12URL = nil }
            }
        }
    }

    private var certificatesSection: some View {
        Section("Signing certificates (.p12)") {
            if store.certificates.isEmpty {
                Text("None yet — import your .p12 below.")
                    .foregroundColor(.secondary)
            }
            ForEach(store.certificates) { cert in
                HStack {
                    Image(systemName: "key.fill").foregroundColor(.accentColor)
                    VStack(alignment: .leading) {
                        Text(cert.label)
                        Text(cert.fileName).font(.caption).foregroundColor(.secondary)
                    }
                }
            }
            .onDelete { idx in idx.map { store.deleteCertificate(store.certificates[$0]) } }
            Button { importingP12 = true } label: {
                Label("Import .p12", systemImage: "plus.circle")
            }
        }
    }

    private var profilesSection: some View {
        Section("Provisioning profiles (.mobileprovision)") {
            if store.profiles.isEmpty {
                Text("None yet — import your .mobileprovision below.")
                    .foregroundColor(.secondary)
            }
            ForEach(store.profiles) { item in
                ProfileRow(profile: item.profile)
            }
            .onDelete { idx in idx.map { store.deleteProfile(store.profiles[$0]) } }
            Button { importingProfile = true } label: {
                Label("Import .mobileprovision", systemImage: "plus.circle")
            }
        }
    }

    private func handleP12Import(_ result: Result<URL, Error>) {
        if case .success(let url) = result, url.startAccessingSecurityScopedResource() {
            defer { url.stopAccessingSecurityScopedResource() }
            p12URL = url
            p12Password = ""
            p12Label = url.deletingPathExtension().lastPathComponent
            showPasswordPrompt = true
        }
    }

    private func handleProfileImport(_ result: Result<URL, Error>) {
        if case .success(let url) = result, url.startAccessingSecurityScopedResource() {
            defer { url.stopAccessingSecurityScopedResource() }
            do { try store.importProfile(from: url); error = nil }
            catch let e { error = e.localizedDescription }
        }
    }

    private func confirmP12Import() {
        guard let url = p12URL else { return }
        do {
            try store.importP12(from: url, password: p12Password,
                                label: p12Label.isEmpty ? "Certificate" : p12Label)
            error = nil
        } catch let e { error = e.localizedDescription }
        p12URL = nil
    }
}

private struct ProfileRow: View {
    let profile: ProvisioningProfile

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: "doc.badge.gearshape")
                    .foregroundColor(profile.isExpired ? .red : .accentColor)
                Text(profile.name).lineLimit(1)
                Spacer()
                if profile.isExpired {
                    Text("EXPIRED").font(.caption).bold().foregroundColor(.red)
                }
            }
            Text("\(profile.teamName) · \(profile.applicationIdentifier)")
                .font(.caption).foregroundColor(.secondary)
            Text("Expires \(profile.expiration, style: .date)")
                .font(.caption).foregroundColor(.secondary)
        }
        .padding(.vertical, 2)
    }
}
