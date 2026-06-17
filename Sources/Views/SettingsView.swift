import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    @State private var vanityPrefix = ""
    @State private var vanityStatus = ""
    @State private var panicPass = ""
    @State private var decoyPass = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Your Identity") {
                    LabeledContent("Address") {
                        Text(appState.ourOnionAddress.isEmpty ? "Loading..." : appState.ourOnionAddress + ".onion")
                            .font(.caption.monospaced())
                            .lineLimit(1)
                    }
                    LabeledContent("Fingerprint") {
                        Text(appState.ourFingerprint)
                            .font(.caption.monospaced())
                    }
                }

                Section("Custom .onion Address") {
                    Text("Generate an address starting with your chosen prefix.\nThis may take seconds to days depending on prefix length. (a-z, 2-7 only)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    HStack {
                        TextField("prefix (e.g. epip)", text: $vanityPrefix)
                            .textFieldStyle(.roundedBorder)
                        Button("Generate") { startVanity() }
                            .buttonStyle(.bordered)
                    }
                    if !vanityStatus.isEmpty {
                        Text(vanityStatus)
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }

                Section("Security") {
                    HStack {
                        SecureField("Panic wipe passphrase", text: $panicPass)
                        Button("Set") {
                            appState.setPanic(panicPass)
                            panicPass = ""
                        }.buttonStyle(.bordered)
                    }
                    HStack {
                        SecureField("Decoy mode passphrase", text: $decoyPass)
                        Button("Set") {
                            appState.setDecoy(decoyPass)
                            decoyPass = ""
                        }.buttonStyle(.bordered)
                    }
                }

                Section("About") {
                    LabeledContent("Version", value: "2.0.0")
                    LabeledContent("Encryption", value: "X3DH + Double Ratchet")
                    LabeledContent("Transport", value: "Tor Hidden Service v3")
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func startVanity() {
        let pfx = vanityPrefix.lowercased()
        guard !pfx.isEmpty else { return }
        let valid = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz234567")
        guard pfx.unicodeScalars.allSatisfy({ valid.contains($0) }) else {
            vanityStatus = "Invalid chars! Use a-z, 2-7 only."
            return
        }
        vanityStatus = "Searching..."
        appState.generateVanity(prefix: pfx)
    }
}
