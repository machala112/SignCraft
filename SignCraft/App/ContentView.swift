import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            AppsView()
                .tabItem {
                    Label("Apps", systemImage: "app.badge")
                }
            CertificatesView()
                .tabItem {
                    Label("Certificates", systemImage: "key.fill")
                }
        }
    }
}
