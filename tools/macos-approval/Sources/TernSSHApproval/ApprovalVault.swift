import ApprovalCore
import CryptoKit
import Foundation
import LocalAuthentication
import Security

private struct StoredEnrollment: Codable {
    let bearer: String
    let hardwareEnvelope: Data
    let publicKey: Data
}

struct ApprovalVault {
    static let bundleID = "dev.ternssh.CommandApproval"
    private let keychain: SecKeychain
    private let access: SecAccess
    private let trustedAppData: Data
    private let account: String

    // A specific ad hoc release is an identity via its implicit cdhash
    // requirement. A different build needs its own enrollment and web pairing.
    static func validatedBuildHash() throws -> String {
        guard Bundle.main.bundleIdentifier == Self.bundleID else { throw ApprovalError.untrustedBuild }
        var dynamic: SecCode?
        var code: SecStaticCode?
        var info: CFDictionary?
        var dr: SecRequirement?
        var requirementText: CFString?
        guard SecCodeCopySelf([], &dynamic) == errSecSuccess, let dynamic,
              SecCodeCheckValidity(dynamic, [], nil) == errSecSuccess,
              SecCodeCopyStaticCode(dynamic, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let fields = info as? [String: Any], let cdhash = fields[kSecCodeInfoUnique as String] as? Data,
              let flags = fields[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & 0x10002 == 0x10002, // hardened runtime + ad hoc
              (fields[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]).isEmpty,
              SecCodeCopyDesignatedRequirement(code, [], &dr) == errSecSuccess, let dr,
              SecRequirementCopyString(dr, [], &requirementText) == errSecSuccess,
              let requirement = requirementText as String? else { throw ApprovalError.untrustedBuild }
        let hash = cdhash.map { String(format: "%02x", $0) }.joined()
        guard cdhash.count == 20, requirement.lowercased() == "cdhash h\"\(hash)\"" else { throw ApprovalError.untrustedBuild }
        return hash
    }

    init() throws {
        account = trustedOrigin + "#" + (try Self.validatedBuildHash())
        var chain: SecKeychain?
        var app: SecTrustedApplication?
        var appData: CFData?
        var acl: SecAccess?
        guard SecKeychainCopyDefault(&chain) == errSecSuccess, let chain,
              SecTrustedApplicationCreateFromPath(nil, &app) == errSecSuccess, let app,
              SecTrustedApplicationCopyData(app, &appData) == errSecSuccess, let appData,
              SecAccessCreate("TernSSH batch approval enrollment" as CFString, [app] as CFArray, &acl) == errSecSuccess,
              let acl else { throw ApprovalError.keychain }
        keychain = chain
        access = acl
        trustedAppData = appData as Data
    }

    private func checkReadACL(_ item: SecKeychainItem) throws {
        var itemAccess: SecAccess?
        guard SecKeychainItemCopyAccess(item, &itemAccess) == errSecSuccess, let itemAccess else {
            throw ApprovalError.keychain
        }
        guard let readRules = SecAccessCopyMatchingACLList(itemAccess, kSecACLAuthorizationDecrypt) as NSArray?,
              readRules.count > 0 else { throw ApprovalError.keychain }
        let generalRules = SecAccessCopyMatchingACLList(itemAccess, kSecACLAuthorizationAny) as NSArray? ?? []
        for rules in [readRules, generalRules] {
            for entry in rules {
                let acl = entry as! SecACL
                var apps: CFArray?
                var title: CFString?
                var prompt = SecKeychainPromptSelector(rawValue: 0)
                guard SecACLCopyContents(acl, &apps, &title, &prompt) == errSecSuccess,
                      let apps, CFArrayGetCount(apps) == 1 else { throw ApprovalError.keychain }
                let app = (apps as NSArray)[0] as! SecTrustedApplication
                var data: CFData?
                guard SecTrustedApplicationCopyData(app, &data) == errSecSuccess, let data,
                      data as Data == trustedAppData else { throw ApprovalError.keychain }
            }
        }
    }

    private var query: [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: Self.bundleID, kSecAttrAccount: account]
    }

    private func load() throws -> StoredEnrollment? {
        var q = query
        q[kSecMatchSearchList] = [keychain]
        q[kSecReturnRef] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let result, CFGetTypeID(result) == SecKeychainItemGetTypeID() else {
            throw ApprovalError.keychain
        }
        let item = result as! SecKeychainItem
        try checkReadACL(item)
        // Never ask to broaden trust for another executable or silently use
        // another item's record. Fetch by the already-checked item reference.
        var allowed = DarwinBoolean(false)
        guard SecKeychainGetUserInteractionAllowed(&allowed) == errSecSuccess,
              SecKeychainSetUserInteractionAllowed(false) == errSecSuccess else { throw ApprovalError.keychain }
        defer { SecKeychainSetUserInteractionAllowed(allowed.boolValue) }
        var raw: CFTypeRef?
        let fetch: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecMatchItemList: [item], kSecReturnData: true]
        guard SecItemCopyMatching(fetch as CFDictionary, &raw) == errSecSuccess, let data = raw as? Data else {
            throw ApprovalError.keychain
        }
        return try JSONDecoder().decode(StoredEnrollment.self, from: data)
    }

    func enroll(token: String) throws -> String {
        guard token.range(of: "^tmcp_[A-Za-z0-9_-]{43}\\z", options: .regularExpression) != nil else {
            throw ApprovalError.invalidArguments
        }
        if let existing = try load() {
            guard existing.bearer == token else { throw ApprovalError.keychain }
            return existing.publicKey.base64EncodedString()
        }
        guard SecureEnclave.isAvailable else { throw ApprovalError.unavailable }
        let context = LAContext()
        defer { context.invalidate() }
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
              let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.biometryCurrentSet, .privateKeyUsage], nil) else {
            throw ApprovalError.unavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl, authenticationContext: context)
        // Exercise the same wrapped-key restoration and biometric policy used
        // for reviews. This domain-separated local probe can never approve a batch.
        let proofContext = LAContext()
        defer { proofContext.invalidate() }
        proofContext.localizedReason = "Verify Touch ID for this Mac's ternssh enrollment"
        proofContext.localizedFallbackTitle = ""
        proofContext.touchIDAuthenticationAllowableReuseDuration = 0
        let restored = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: key.dataRepresentation,
                                                                 authenticationContext: proofContext)
        let probe = Data(("ternssh/local-enrollment-proof/v1/" + UUID().uuidString).utf8)
        let proof = try restored.signature(for: probe)
        guard key.publicKey.isValidSignature(proof, for: probe) else { throw ApprovalError.keychain }
        let spki = key.publicKey.derRepresentation
        let record = StoredEnrollment(bearer: token, hardwareEnvelope: key.dataRepresentation, publicKey: spki)
        var q = query
        q[kSecUseKeychain] = keychain
        q[kSecAttrAccess] = access
        // Inspect the OS-created item's actual ACL before placing any bearer
        // or hardware envelope in it. Roll back only this newly added record.
        q[kSecValueData] = Data()
        q[kSecReturnRef] = true
        var added: CFTypeRef?
        guard SecItemAdd(q as CFDictionary, &added) == errSecSuccess, let added,
              CFGetTypeID(added) == SecKeychainItemGetTypeID() else { throw ApprovalError.keychain }
        let item = added as! SecKeychainItem
        let exact: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecMatchItemList: [item]]
        do {
            try checkReadACL(item)
            let values: [CFString: Any] = [kSecValueData: try JSONEncoder().encode(record)]
            guard SecItemUpdate(exact as CFDictionary, values as CFDictionary) == errSecSuccess,
                  let verified = try load(), verified.publicKey == spki else { throw ApprovalError.keychain }
        } catch {
            _ = SecKeychainItemDelete(item)
            throw error
        }
        return spki.base64EncodedString()
    }

    func token() throws -> String {
        guard let record = try load() else { throw ApprovalError.keychain }
        return record.bearer
    }

    func forget() throws {
        guard try load() != nil else { return }
        // The service and account include the pinned origin and this
        // binary's code-directory hash. Never act on other builds or records.
        var q = query
        q[kSecMatchSearchList] = [keychain]
        guard SecItemDelete(q as CFDictionary) == errSecSuccess else { throw ApprovalError.keychain }
    }

    func signAfterReview(_ batch: VerifiedBatch) throws -> Data {
        guard batch.expiresAt > Int64(Date().timeIntervalSince1970 * 1000),
              let record = try load() else { throw ApprovalError.unavailable }
        let context = LAContext()
        defer { context.invalidate() }
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = "Approve the displayed ternssh batch \(batch.digest)"
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = "Cancel batch"
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: record.hardwareEnvelope,
                                                                authenticationContext: context)
            guard key.publicKey.derRepresentation == record.publicKey else { throw ApprovalError.keychain }
            let signature = try key.signature(for: batch.signingBytes).rawRepresentation
            guard batch.expiresAt > Int64(Date().timeIntervalSince1970 * 1000) else { throw ApprovalError.expired }
            return signature
        } catch let error as ApprovalError { throw error }
          catch { throw ApprovalError.cancelled }
    }
}
