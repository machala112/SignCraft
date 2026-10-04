import SwiftUI
import UniformTypeIdentifiers

struct AppsView: View {
    @EnvironmentObject var store: AppStore
    @State private var importing = false
    @State private var selectedIPA: IPAFile?

    var body: some View {
        NavigationStack {
            Group {
                if store.ipas.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "app.badge")
                            .font(.system(size: 48))
                            .foregroundColor(.secondary)
                        Text("No apps yet")
                            .font(.headline)
                        Text("Import an .ipa file to sign and install it.")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                } else {
                    List {
                        ForEach(store.ipas) { ipa in
                            Button { selectedIPA = ipa } label: {
                                HStack {
                                    Image(systemName: "app.fill")
                                        .foregroundColor(.accentColor)
                                    VStack(alignment: .leading) {
                                        Text(ipa.fileName)
                                            .lineLimit(1)
                                        Text(ipa.displaySize)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                            }
                        }
                        .onDelete { idx in idx.map { store.deleteIPA(store.ipas[$0]) } }
                    }
                }
            }
            .navigationTitle("SignCraft")
            .toolbar {
                Button { importing = true } label: {
                    Label("Import IPA", systemImage: "plus")
                }
            }
            .fileImporter(isPresented: $importing,
                          allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data]) { result in
                if case .success(let url) = result, url.startAccessingSecurityScopedResource() {
                    defer { url.stopAccessingSecurityScopedResource() }
                    try? store.importIPA(from: url)
                }
            }
            .sheet(item: $selectedIPA) { ipa in
                SignFlowView(ipa: ipa)
                    .environmentObject(store)
            }
        }
    }
}
