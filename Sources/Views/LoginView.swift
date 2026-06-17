import SwiftUI

struct LoginView: View {
    @EnvironmentObject var appState: AppState
    @State private var passphrase = ""
    @State private var confirmPassphrase = ""
    @State private var useBridges = false
    @State private var isCreateMode = false
    @State private var errorMessage = ""

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            Text("🌿 Epiphyte")
                .font(.system(size: 32, weight: .bold))

            Text("End-to-end encrypted messenger")
                .font(.subheadline)
                .foregroundColor(.secondary)

            // Mode toggle
            Picker("", selection: $isCreateMode) {
                Text("Login").tag(false)
                Text("Create Account").tag(true)
            }
            .pickerStyle(.segmented)
            .frame(width: 280)

            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)

            if isCreateMode {
                SecureField("Confirm passphrase", text: $confirmPassphrase)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 280)
            }

            Toggle("Use bridges (China, Iran, etc.)", isOn: $useBridges)
                .frame(width: 280)
                .font(.caption)

            if !errorMessage.isEmpty {
                Text(errorMessage)
                    .foregroundColor(.red)
                    .font(.caption)
            }

            Button(isCreateMode ? "Create & Enter" : "Unlock") {
                unlock()
            }
            .buttonStyle(.borderedProminent)
            .frame(width: 280, height: 44)
            .disabled(passphrase.isEmpty)

            if isCreateMode {
                Text("This creates a new identity with a fresh encryption key.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            } else {
                Text("Enter your passphrase to unlock your identity.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            Spacer()

            Text("v2.0.0")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding()
    }

    private func unlock() {
        errorMessage = ""

        if isCreateMode {
            guard passphrase.count >= 4 else { errorMessage = "Passphrase must be at least 4 characters."; return }
            guard passphrase == confirmPassphrase else { errorMessage = "Passphrases don't match!"; return }
        }

        appState.useBridges = useBridges

        if appState.unlock(passphrase: passphrase, isNewAccount: isCreateMode) {
            appState.connectTor()
        } else {
            errorMessage = "Wrong passphrase."
        }
    }
}
