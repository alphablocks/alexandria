// Native-only sidecar. No secret is accepted through command-line arguments.
import Foundation
import Security
import AppKit

func fail() -> Never {
    FileHandle.standardError.write(Data("KEYCHAIN_ERROR\n".utf8)); exit(1)
}
let service = "org.alexandria.vault"
let args = CommandLine.arguments
guard args.count >= 2 else { fail() }
if args[1] == "watch" {
    // The native parent holds this pipe open. Exit when it goes away instead
    // of leaving a background observer after the desktop app has exited.
    Thread.detachNewThread {
        _ = FileHandle.standardInput.readDataToEndOfFile()
        exit(0)
    }
    let output = FileHandle.standardOutput
    func event(_ text: String) { output.write(Data((text + "\n").utf8)) }
    let ws = NSWorkspace.shared.notificationCenter
    for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification] {
        ws.addObserver(forName: name, object: nil, queue: .main) { _ in event("LOCK") }
    }
    DistributedNotificationCenter.default().addObserver(
        forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil,
        queue: .main) { _ in event("LOCK") }
    event("READY")
    RunLoop.main.run()
    exit(0)
}
let action = args[1]
let connector = action.contains("connector")
guard !connector || (args.count == 3 && UUID(uuidString: args[2]) != nil) else { fail() }
let account = connector ? "connector-" + args[2] : "vault-key"
let base: [CFString: Any] = [kSecClass:kSecClassGenericPassword,
    kSecAttrService:service, kSecAttrAccount:account, kSecAttrSynchronizable:false]
if action.hasPrefix("set-") {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard data.count == 64, let value = String(data:data,encoding:.utf8),
          value.allSatisfy({$0.isHexDigit}) else { fail() }
    // No replacement of an existing vault key: never orphan its database.
    var item = base
    item[kSecValueData] = data
    if connector {
        item[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    } else {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error) else { fail() }
        item[kSecAttrAccessControl] = access
    }
    guard SecItemAdd(item as CFDictionary,nil) == errSecSuccess else { fail() }
} else if action.hasPrefix("get-") {
    var query = base
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne
    if !connector { query[kSecUseOperationPrompt] = "Unlock your Alexandria memory vault" }
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary,&result) == errSecSuccess,
          let data = result as? Data else { fail() }
    FileHandle.standardOutput.write(data)
} else if action.hasPrefix("delete-") {
    let status = SecItemDelete(base as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { fail() }
} else { fail() }
