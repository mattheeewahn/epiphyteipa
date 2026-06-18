import SwiftUI

struct MainView: View {
    @EnvironmentObject var appState: AppState
    @State private var newContactAddress = ""
    @State private var messageText = ""
    @State private var showSettings = false

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            chatArea
        }
        .sheet(isPresented: $showSettings) {
            SettingsView()
                .environmentObject(appState)
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("🌿 Epiphyte")
                    .font(.headline)
                Spacer()
                statusDot
                Button(action: { showSettings = true }) {
                    Image(systemName: "gearshape")
                }
            }
            .padding()

            // Add contact
            HStack {
                TextField("Add .onion address...", text: $newContactAddress)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { addContact() }
                Button("+") { addContact() }
                    .buttonStyle(.bordered)
            }
            .padding(.horizontal)
            .padding(.bottom, 8)

            // Contact list
            List(appState.contacts.filter { !$0.blocked }, selection: $appState.currentPeer) { contact in
                ContactRow(contact: contact)
                    .tag(contact.onionAddress)
            }

            // Our address
            Text(appState.ourOnionAddress.isEmpty ? "Connecting..." : "\(appState.ourOnionAddress.prefix(16))...onion")
                .font(.caption2)
                .foregroundColor(.secondary)
                .padding(8)
                .onTapGesture { copyAddress() }
        }
        .frame(minWidth: 250)
    }

    // MARK: - Chat

    private var chatArea: some View {
        VStack(spacing: 0) {
            if let peer = appState.currentPeer {
                // Chat header
                HStack {
                    let contact = appState.contacts.first { $0.onionAddress == peer }
                    Text(contact?.displayName ?? peer.prefix(16) + "...")
                        .font(.headline)
                    Text(contact?.status == .connected ? "🔒 Encrypted" : "(\(contact?.status.rawValue ?? "offline"))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .padding()

                Divider()

                // Messages
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 8) {
                            ForEach(appState.messages[peer] ?? []) { msg in
                                MessageBubble(message: msg)
                                    .id(msg.id)
                            }
                        }
                        .padding()
                    }
                    .onChange(of: appState.messages[peer]?.count) { _ in
                        if let last = appState.messages[peer]?.last {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }

                Divider()

                // Input
                HStack {
                    Button(action: attachFile) {
                        Image(systemName: "paperclip")
                    }
                    TextField("Type a message...", text: $messageText)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { sendMessage() }
                    Button("Send") { sendMessage() }
                        .buttonStyle(.borderedProminent)
                        .disabled(messageText.isEmpty)
                }
                .padding()
            } else {
                Text("Select a contact to start chatting")
                    .foregroundColor(.secondary)
            }
        }
    }

    private var statusDot: some View {
        Circle()
            .fill(appState.connectionStatus == .connected ? Color.green :
                    appState.connectionStatus == .connecting ? Color.yellow : Color.gray)
            .frame(width: 8, height: 8)
    }

    // MARK: - Actions

    private func addContact() {
        guard !newContactAddress.isEmpty else { return }
        appState.addContact(newContactAddress)
        newContactAddress = ""
    }

    private func sendMessage() {
        guard let peer = appState.currentPeer, !messageText.isEmpty else { return }
        appState.sendMessage(to: peer, text: messageText)
        messageText = ""
    }

    private func attachFile() {
        // File picker - platform dependent
    }

    private func copyAddress() {
        #if os(iOS)
        UIPasteboard.general.string = appState.ourOnionAddress + ".onion"
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(appState.ourOnionAddress + ".onion", forType: .string)
        #endif
    }
}

// MARK: - Contact Row

struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack {
            Circle()
                .fill(contact.status == .connected ? Color.green : Color.gray)
                .frame(width: 10, height: 10)
            VStack(alignment: .leading) {
                Text(contact.displayName)
                    .font(.subheadline.bold())
                Text(contact.status.rawValue)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Message Bubble

struct MessageBubble: View {
    let message: ChatMessage

    var body: some View {
        if message.isSystem {
            HStack {
                Spacer()
                Text("─── \(message.text) ───")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
            }
        } else {
            HStack {
                if message.isOurs { Spacer() }
                VStack(alignment: message.isOurs ? .trailing : .leading, spacing: 2) {
                    Text(message.text)
                        .padding(10)
                        .background(message.isOurs ? Color.blue : Color.gray.opacity(0.3))
                        .foregroundColor(message.isOurs ? .white : .primary)
                        .cornerRadius(16)
                    Text(timeString)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                if !message.isOurs { Spacer() }
            }
        }
    }

    private var timeString: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f.string(from: message.timestamp)
    }
}
