# Alexandria local memory vault

**Windows-first desktop prototype. The real Windows/MSVC build produced an unsigned installer and validated Claude extension. Interactive Windows Hello, installation, session/recovery UI and live Claude pairing are not yet verified; this is not a production-security claim.**

Your vault stays on your computer. Local use needs no Alexandria account or hosted database. The native app manages records, exact-text provenance, versions, connection grants, save proposals, exports and encrypted recovery backups. There is no new chat interface. Approved content retrieved by Claude leaves your computer and is subject to the assistant provider's policies. The public website explains and distributes the desktop vault; the existing dataset API is a separate service.

## What runs here

The Rust contract tests run on Linux against real bundled SQLCipher, real age encryption, real Unix sockets and newline-framed MCP protocol handling. The React UI typechecks and builds. Browser-only mode deliberately refuses vault access—there is no mock-data, localStorage or network fallback.

The Windows implementation uses current-user DPAPI for the local vault-key file, Credential Manager for separate connector tokens, Windows Hello desktop-window interop for owner verification, a SID-restricted named pipe, and a WTS/power-event observer. These are Windows APIs, not home-grown encryption or an HTTP fallback.

The Windows/MSVC CI run passed 15 core tests, 5 Windows security tests, the native app/NSIS build and MCPB validation. See `VERIFICATION.md` for actual evidence and the interactive checks still open. Do not put irreplaceable or sensitive personal data into this prototype.

## Download the unsigned Windows prototype

The [public prototype release](https://github.com/alphablocks/alexandria/releases/tag/windows-prototype-0.1.0) distributes the same binaries from the successful [Windows build](https://github.com/alphablocks/alexandria/actions/runs/41286112047):

- [Windows x64 installer](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/Alexandria-Windows-x64-setup.exe)
- [Claude Desktop extension](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/Alexandria-Windows.mcpb)
- [SHA-256 checksums](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/SHA256SUMS.txt)

Requires Windows 11 x64 and Windows Hello configured. Follow the Windows first-use steps below; keep the app open and unlocked for Claude access. This is unsigned: do not bypass Windows or organization restrictions to install it. Test with non-sensitive sample data first.

## Source layout

- `core/`: SQLCipher records/authorization, proposals, portability, age recovery, private socket and MCP protocol.
- `native/`: Tauri owner command, native file dialogs and platform integration.
- `windows-platform/`: independently compiler-checkable Windows protection, credentials, ACLs, Hello interop, named pipes and session/power observer.
- `src/`: real native-command UI; no vault keys are passed into React.
- `mcpb/manifest.json`: packaged Claude Desktop adapter manifest. Its binaries are generated locally.
- `scripts/package-macos.sh`: builds the native helper and adapter on Apple Silicon macOS.
- `scripts/package-windows.ps1`: builds the Windows adapter and optionally packs the Claude extension.
- `.github/workflows/windows-vault.yml` at the repository root: Windows test/build/unsigned packaging workflow, with a recorded successful run linked above.

## Core development and verification

From the workspace root:

```sh
pnpm install --frozen-lockfile
cargo test --manifest-path desktop/alexandria-vault/Cargo.toml -p alexandria-vault-core --locked
pnpm --filter @workspace/alexandria-vault typecheck
pnpm --filter @workspace/alexandria-vault build
```

Rust 1.88 is the tested Linux compiler. The UUID dependency is pinned to a release compatible with it. `Cargo.lock` fixes the resolved native and core dependency graph. SQLCipher bundles OpenSSL; a C compiler, make and Perl are required for that build. First compilation may take several minutes. SQLCipher/OpenSSL artifacts and native binaries are ignored in Git and excluded from deployment.

## Windows: developer build

First supported configuration: **Windows 11 x64**, Windows Hello configured (PIN, face or fingerprint), an interactive signed-in user, and a local NTFS location supporting owner-only ACLs. Desktop consent interop requires Windows build 22000 or later. Other architectures, Windows 10, redirected application-data directories and non-ACL filesystems are not supported by this first package.

Install the official prerequisites:

- Microsoft C++ Build Tools with **Desktop development with C++**, Windows SDK and MSVC x64.
- Microsoft Edge WebView2 Evergreen runtime.
- Rust 1.90.0 MSVC toolchain (required by the locked Tauri version); Node 24 and pnpm 10.26.1. The core/security module alone also checks on Rust 1.88.
- Git for Windows (including its sh shell), Strawberry Perl for bundled OpenSSL. NASM is optional with the documented build setting.
- Claude Desktop with custom local extensions permitted by its organization policy.

In a developer PowerShell terminal with those tools available:

```powershell
# Change these tool locations if installed elsewhere.
$env:Path = "C:\Program Files\Git\bin;C:\Strawberry\perl\bin;$env:Path"
$env:OPENSSL_SRC_PERL = "C:\Strawberry\perl\bin\perl.exe"
$env:OPENSSL_RUST_USE_NASM = "0"
$env:CARGO_BUILD_JOBS = "4"
rustup toolchain install 1.90.0 --profile minimal --component rustfmt
rustup override set 1.90.0
pnpm install --frozen-lockfile
cargo test --manifest-path desktop/alexandria-vault/Cargo.toml --locked -p alexandria-vault-core -p alexandria-windows -- --test-threads=1
pnpm --filter @workspace/alexandria-vault desktop
```

Run from the repository root, with no other Alexandria instance running for the named-pipe tests. The root package's existing preinstall hook needs sh; installing only Rust and Node is not enough.

### Build the Windows installer and Claude extension

```powershell
pnpm --filter @workspace/alexandria-vault desktop:build
./desktop/alexandria-vault/scripts/package-windows.ps1 -PackExtension
```

If these builds succeed on Windows, the current-user NSIS installer is under `desktop/alexandria-vault/target/release/bundle/nsis/`. The packaged extension is `generated-artifacts/Alexandria-Windows.mcpb`. The app build and extension build are separate; failure in either is not a successful installation.

The linked CI run produced a real installer and executed the unattended Windows tests. Interactive installation and app use on Windows 11 are not yet verified. This is not a signed consumer distribution. Do not disable OS, browser, execution-policy or organizational protections to run it. Signing/release validation is a separate requirement.

The repository includes a **Windows local memory vault** GitHub Actions workflow. The successful run linked above uploaded the unsigned installer and extension together as an artifact; the publication workflow verified and distributed those files as the public prototype release. CI tests do not substitute for interactive Hello, actual screen lock/suspend, native recovery dialogs or live Claude verification.

### Use the Windows app with Claude

1. Open the native app, create the vault and approve the Windows Hello prompt.
2. Add a synthetic memory. Create a connection in **Connections**, grant that record and leave proposals off until needed.
3. Install the generated `.mcpb` in Claude Desktop's custom extension settings and enter that connection's non-secret ID.
4. The adapter obtains only its connector token from Windows Credential Manager. It cannot read the DPAPI vault-key file through the protocol or unlock the service.
5. Keep the app open and unlocked. Test retrieval, optional proposal approval, revocation and locking before real data.

Windows data is under the shell-known LocalAppData folder, normally `%LOCALAPPDATA%\Alexandria`. The key file is DPAPI ciphertext and the database is SQLCipher ciphertext. The service uses a local-only current-SID named pipe, not a TCP port. Imported content does not acquire new grants. Session unlock/resume reopens only the availability gate, never the database; a fresh owner-approved unlock remains necessary.

The local client acknowledges each complete response before the server closes its pipe. This bounded handshake prevents unread-response loss without holding up owner revocation. Update the app and adapter together; it is a private local transport contract, not an extra message sent to Claude's MCP stdio.

DPAPI alone is **not** owner presence. The native app verifies Hello before loading the key and rejects a changed session epoch. A lock event closes an atomic service gate before waiting for the database mutex. Stale UI status responses cannot supersede a newer locked status. An unavailable monitor, unsupported security API or failed ACL check denies the operation.

DPAPI current-user protection is not an absolute device-binding promise: Windows roaming/domain profiles can have different recovery behavior. Another process running as the same user, an administrator or a compromised unlocked OS remains outside this prototype's protection.

## Legacy Mac developer build

Prerequisites: Apple Silicon Mac, macOS 12+, Xcode Command Line Tools (including Swift), a Rust toolchain compatible with the locked dependencies, Node/pnpm and Claude Desktop with local extensions permitted. This is a source-build path for developers; a signed consumer installer is not yet available.

From the workspace root:

```sh
pnpm install --frozen-lockfile
bash desktop/alexandria-vault/scripts/package-macos.sh
pnpm --filter @workspace/alexandria-vault desktop
```

For an app/DMG build:

```sh
pnpm --filter @workspace/alexandria-vault desktop:build
```

The native helper must be built first. Tauri packages it as a sidecar. Release signing/notarization requires the developer's own Apple signing setup; no signing identity or credentials are provided, collected in chat or bypassed by these instructions. An unsigned local build is not evidence of a distributable trusted app.

### First use

1. Open Alexandria and choose **Create encrypted vault**. The app protects a random key with current-user DPAPI and requests Windows Hello verification on Windows, or uses device Keychain on Mac. It refuses to open if encryption or the lock observer is unavailable.
2. Add a memory. It is private by default. Source labels are supplied metadata, not verified access to a provider transcript.
3. Open **Connections**, pair a labeled installation and select individual existing records. Read-only is the default. New records are not included automatically.
4. To allow assistant saves, enable proposals into one scope. Every proposal still requires approval under **Review**. PENDING_APPROVAL is not a committed memory.
5. Create an encrypted backup. Save its recovery identity separately and test recovery into a fresh vault before relying on it.

The legacy Mac store is `~/Library/Application Support/org.alexandria.vault/vault.db`; the Windows location is described above. The service starts locked. Screen lock/sleep notifications, manual lock and 15 minutes without owner interaction close it. Connector traffic and polling do not renew that timer. These native behaviors require target-platform verification before being trusted.

### Legacy Mac Claude Desktop extension

After running the packaging script, `mcpb/server/` contains the compiled adapter and its Keychain helper. Use the official MCPB tool to validate and pack that directory:

```sh
pnpm dlx @anthropic-ai/mcpb validate desktop/alexandria-vault/mcpb/manifest.json
pnpm dlx @anthropic-ai/mcpb pack desktop/alexandria-vault/mcpb
```

These packaging commands require access to the official package registry and are **not recorded as executed here**. Check the current tool's help if its CLI changes. Install the resulting `.mcpb` through Claude Desktop's custom extension settings. Enter the non-secret connection ID shown by the native app. The adapter reads its actual credential from macOS Keychain, never from command-line tokens or a plaintext config file.

The initial extension installation plus app pairing are explicit steps. Organization policy may prohibit extensions; do not bypass it. Test initialize, tools/list, actual permitted retrieval, a pending proposal, approval, revocation and lock on the target machine. Local MCP results are still sent to Anthropic when Claude uses them.

## Security boundaries

- The owner management command is available only inside the trusted local Tauri window. The socket accepts four connector tools, not owner operations or arbitrary SQL/files.
- Connection names are labels. Authentication uses a distinct installation credential; another same-user process that steals it can impersonate that installation.
- Permissions filter current approved records before matching/ranking. Proposed inferences and superseded history are owner-only. Quoted instructions cannot grant permission.
- New writes are proposals with transaction receipts after owner approval. Stale updates fail with CONFLICT.
- Revocation and socket response dispatch share a mutex. Responses already dispatched can arrive later and cannot be recalled.
- Wrong keys/corruption fail closed. The UI never obtains a database key. Unlocked native processes, the OS and intentionally shared provider tool results can contain plaintext.
- There is no remote relay, ChatGPT connection, telemetry or automatic cloud copy in this implementation.

This does not protect an unlocked compromised computer, an administrator, malware running as the user, screenshots, accessibility capture, OS swap or independent provider retention. It has not had a cryptographic or distribution security audit.

## Export, backup and deletion

**Plaintext export:** JSON plus readable Markdown, with a warning and native save dialog. Files use new names; existing files are never silently overwritten. JSON preserves record fields and history. Markdown is a readable companion, not a lossless backup. Opening untrusted Markdown in another renderer is outside this app's controls.

**Import:** preview first, then revalidate/commit atomically. Equal records deduplicate. Conflicting versions or attempts to merge new versions into existing live history are blocked, not silently resolved. New imported records have no grants. Existing identical records keep their existing explicit grants. The format is an Alexandria draft, not an adopted interoperability standard.

**Encrypted backup:** age-encrypted envelope containing a consistent SQLCipher snapshot and its database key. The key and unencrypted envelope stay in native memory, not plaintext temporary files. Temporary snapshot files are themselves encrypted. Each backup has a generated separate recovery identity; it is never returned to the renderer, copied to clipboard or uploaded.

**Restore:** only into a fresh vault. Pick encrypted backup and separate identity, review the count, then confirm. Verify integrity and manifest in staging, import content into a fresh operational vault/key, and leave old connection credentials/grants/proposals behind. If the vault still exists, use portable import instead—do not delete a working vault to try recovery.

**Lost recovery material:** no reset or backdoor. A working unlocked vault can create a new backup with a new identity. That does not revoke old backup copies. A lost device plus lost recovery identity can mean permanent loss.

**Deletion:** removes live content, all record versions and linked proposal content/grants. Secure-delete/VACUUM maintain the live database; forensic erasure from SSDs, filesystem snapshots, exports, user backups or provider conversations is not promised. Application backups are manual, with no hidden retention schedule. Audit events contain operation names/timestamps only and expire after seven days. Proposal text expires after 24 hours; bounded content-free operation receipts remain to prevent retry duplication until the connection is revoked.

## Prototype limits

10,000 record IDs, 50,000 total versions and a 48 MiB serialized-record budget keep portable exports within the 50 MiB import limit. Each record has at most 32 KiB of UTF-8 text. Search returns at most 20 records and bounded tool responses; refine the query when bounded. No remote embeddings.

Pending proposals: 20 per connection, expiring after 24 hours. Each connection may retain up to 10,000 operation receipts; pair a new connection after revoking an exhausted one. Grants may be assigned only to active records. Scope changes require a new record instead of silently moving shared content.

Encrypted database snapshots are limited to 64 MiB; larger vaults can still use portable JSON export, but this prototype rejects an oversized recovery snapshot explicitly. Recovery envelopes are strict JSON with no archive-path extraction. Preview buffers expire after 15 minutes and are cleared on native lock notifications.

## Licensing and status

Alexandria-owned code uses the repository's MIT license. Rust, SQLCipher, OpenSSL, age, Tauri and UI dependencies retain their own licenses. Their exact pinned licenses and binary redistribution notices still need release review. No Basic Memory/AGPL implementation was copied.

The implementation source and Windows CI definition are here. Windows/MSVC installer execution, interactive native runtime and live Claude checks are not claimed verified. Legacy macOS runtime is also unverified. ChatGPT/remote bridges and automatic history collection are intentionally absent.

## Primary platform references

- Tauri Windows prerequisites: https://v2.tauri.app/start/prerequisites/#windows
- Desktop owner verification (Windows build 22000+): https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync
- DPAPI protection and roaming caveat: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- Named-pipe access control: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- Remote-client rejection: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
