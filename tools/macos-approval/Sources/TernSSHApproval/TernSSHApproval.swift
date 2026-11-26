import AppKit
import ApprovalCore
import CryptoKit
import Foundation

@main @MainActor
struct TernSSHApproval {
    static func emit(_ fields: [String: String]) {
        guard let data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]) else { return }
        FileHandle.standardOutput.write(data + Data([10]))
    }

    static func prepareUI() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let menu = NSMenu()
        let edit = menu.addItem(withTitle: "Edit", action: nil, keyEquivalent: "")
        let submenu = NSMenu(title: "Edit")
        submenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        submenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.submenu = submenu
        app.mainMenu = menu
        app.activate(ignoringOtherApps: true)
    }

    static func enroll(_ vault: ApprovalVault) throws {
        let alert = NSAlert()
        alert.messageText = "Enroll this Mac for ternssh batch approval"
        alert.informativeText = "Enter the pairing token from \(trustedOrigin). This Mac keeps the token and a device-bound approval key. Register the resulting public key on that pairing."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 460, height: 28))
        field.placeholderString = "Pairing token"
        alert.accessoryView = field
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Enroll")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertSecondButtonReturn else { throw ApprovalError.cancelled }
        let spki = try vault.enroll(token: field.stringValue)
        field.stringValue = ""
        guard let der = Data(base64Encoded: spki) else { throw ApprovalError.keychain }
        let fingerprint = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        emit(["publicKeySpki": spki, "fingerprint": fingerprint])
        let result = NSAlert()
        result.messageText = "Register this public key on the pairing"
        result.informativeText = "SHA-256  " + fingerprint + "\n\n" + spki
        result.addButton(withTitle: "Done")
        result.addButton(withTitle: "Copy Public Key")
        if result.runModal() == .alertSecondButtonReturn {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(spki, forType: .string)
        }
    }

    static func review(_ batch: VerifiedBatch) -> Bool {
        let alert = NSAlert()
        alert.messageText = "Review this SSH command batch"
        alert.informativeText = "Review the target and every command before approving. Touch ID will authorize this exact batch."
        let tab = NSTabView(frame: NSRect(x: 0, y: 0, width: 610, height: 350))
        for (label, contents) in [("Commands", batch.review), ("UTF-8 bytes", batch.byteReview)] {
            let item = NSTabViewItem(identifier: label)
            item.label = label
            item.view = reviewText(contents)
            tab.addTabViewItem(item)
        }
        alert.accessoryView = tab
        alert.addButton(withTitle: "Decline")
        alert.addButton(withTitle: "Approve Exact Batch")
        return alert.runModal() == .alertSecondButtonReturn
    }

    static func reviewText(_ value: String) -> NSScrollView {
        let view = NSScrollView(frame: NSRect(x: 0, y: 0, width: 590, height: 320))
        view.hasVerticalScroller = true
        view.borderType = .bezelBorder
        let text = NSTextView(frame: NSRect(origin: .zero, size: view.contentSize))
        text.isEditable = false
        text.isSelectable = true
        text.isRichText = false
        text.isVerticallyResizable = true
        text.autoresizingMask = [.width]
        text.textContainer?.widthTracksTextView = true
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        text.string = value
        view.documentView = text
        return view
    }

    static func main() async {
        var args = Array(CommandLine.arguments.dropFirst())
        var receipt: [String: String] = ["status": "failed"]
        do {
            if args == ["verify-build"] {
                emit(["cdhash": try ApprovalVault.validatedBuildHash()])
                return
            }
            prepareUI()
            let vault = try ApprovalVault()
            if args.isEmpty {
                let choose = NSAlert()
                choose.messageText = "TernSSH batch approval"
                choose.informativeText = trustedOrigin
                choose.addButton(withTitle: "Close")
                choose.addButton(withTitle: "Enroll")
                choose.addButton(withTitle: "Remove Enrollment")
                switch choose.runModal() {
                case .alertSecondButtonReturn: args = ["enroll"]
                case .alertThirdButtonReturn: args = ["forget"]
                default: return
                }
            }
            if args == ["enroll"] { try enroll(vault); return }
            if args == ["forget"] {
                let ask = NSAlert()
                ask.messageText = "Remove this Mac's local test enrollment?"
                ask.informativeText = "Remove the wrapped approval key and pairing token from this build's login Keychain item. Revoke the pairing separately in ternssh."
                ask.addButton(withTitle: "Cancel")
                ask.addButton(withTitle: "Remove Enrollment")
                guard ask.runModal() == .alertSecondButtonReturn else { throw ApprovalError.cancelled }
                try vault.forget()
                emit(["status": "forgotten"])
                return
            }
            guard args.count == 3, args[0] == "review", args[1].utf8.count <= 128, !args[1].isEmpty,
                  UUID(uuidString: args[2])?.uuidString.lowercased() == args[2] else { throw ApprovalError.invalidArguments }
            receipt["serverId"] = args[1]
            receipt["batchId"] = args[2]
            let client = PairingClient(bearer: try vault.token())
            defer { client.close() }
            try await client.initialize()
            let batch = try await client.getBatch(server: args[1], batch: args[2])
            guard review(batch) else {
                receipt["status"] = "declined"
                emit(receipt)
                return
            }
            let signature = try vault.signAfterReview(batch)
            try await client.approve(server: args[1], batch: args[2], reviewed: batch, signature: signature)
            receipt["status"] = "approved"
        } catch ApprovalError.cancelled {
            receipt["status"] = "cancelled"
        } catch ApprovalError.uncertain {
            receipt["status"] = "unknown"
        } catch {
            // A localized networking or keychain exception can contain private
            // data. The caller only needs a disposition and the submitted IDs.
        }
        emit(receipt)
    }
}
