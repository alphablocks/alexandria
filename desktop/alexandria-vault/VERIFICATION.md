# Alexandria vault — implementation verification

Verified on 1 November 2026 in Linux and a Windows Server 2022 CI runner. The CI workflow produced an unsigned Windows x64 installer and Claude MCPB artifact. **This is not interactive Windows 11 desktop/Hello verification, live Claude integration testing, or a security audit.**

## Latest Windows port

Windows is now the initial desktop target. Windows 11 x64 with Windows Hello is the first supported prototype configuration. The public website now explains the desktop vault and offers public downloads; the existing dataset API remains unchanged.

| Check | Actual outcome |
| --- | --- |
| Linux core contract suite after the port and transport fix | PASS — 19 tests, 0 failures |
| Windows security library and its Windows tests | PASS — 5 security tests and 15 core contract tests passed on Windows Server 2022/MSVC |
| Core, adapter and core test targets for Windows GNU | PASS for Windows-target compiler check only; not executed or linked into a distributable executable |
| Native Tauri/MSVC app and NSIS installer | PASS — built successfully on Windows Server 2022/MSVC in workflow run [41286112047](https://github.com/alphablocks/alexandria/actions/runs/41286112047); unsigned prototype |
| UI TypeScript check and production build | PASS |
| Claude Windows MCPB extension | PASS — built and validated in workflow run 41286112047; installation into Claude was not tested |
| Formatting and whitespace check | PASS |
| Public website | PASS — explains the vault, installation and privacy boundaries; desktop/mobile screenshots checked; all three public download URLs return HTTP 200 without credentials |
| Public binary distribution | PASS — original build hashes verified before publishing; local anonymous downloads match the published SHA-256 manifest; packaged MCPB command executable is present |
| Windows GitHub Actions workflow | PASS — complete successful build, deliverable verification, and upload in [run 41286112047](https://github.com/alphablocks/alexandria/actions/runs/41286112047). Earlier failed runs: [Run 1](https://github.com/alphablocks/alexandria/actions/runs/41283956938) · [Run 2](https://github.com/alphablocks/alexandria/actions/runs/41285374642) |
| Windows Hello, native UI, WTS/suspend and live Claude | BLOCKED — no interactive authorized Windows session |

### Download provenance and checksums

The [public unsigned prototype release](https://github.com/alphablocks/alexandria/releases/tag/windows-prototype-0.1.0) distributes the original binaries from the successful Windows build. [Publication run 41288451556](https://github.com/alphablocks/alexandria/actions/runs/41288451556) verified the source run/revision, original hashes, Windows executable headers and the MCPB's included executable before publishing. No native app or adapter code changed between the tested source revision and these files.

Both files and `SHA256SUMS.txt` were downloaded without credentials into ignored `generated-artifacts/vault-windows/public-downloads/`. Their hashes were independently recomputed and matched the manifest. The downloaded MCPB's manifest command resolves to the included `server/alexandria-mcp.exe`, which has a Windows executable header. This is package verification, not execution of the installer or live Claude pairing.

| Public download | SHA-256 |
| --- | --- |
| [Alexandria-Windows-x64-setup.exe](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/Alexandria-Windows-x64-setup.exe) | `f60cc6a9998250867f16f12447f8fa63f9b87d132656a682c5099ed273524f48` |
| [Alexandria-Windows.mcpb](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/Alexandria-Windows.mcpb) | `60df5472030acb7d3d5663eeb5b16927c97053cdb9c2656afc6978d571f709d5` |

### What the Windows code implements

- Atomic owner-only file creation and protected DACLs; actual descriptor inspection rejects ineffective ACL protection before writing data. Redirected/reparse paths are rejected.
- LocalAppData from the Windows shell API rather than caller-controlled environment paths.
- Current-user DPAPI vault-key ciphertext and separate installation entries in Credential Manager.
- Desktop HWND-based Windows Hello verification before key loading. DPAPI alone never constitutes owner approval. Session changes invalidate pending authentication.
- WTS/power-event monitoring, atomic availability gating before waiting for the store mutex, and manual/idle locking. Reopening the gate never reopens the store.
- Local SID-restricted named pipes with remote-client rejection, peer process/SID checking, first-instance reservation and deadline-bounded overlapped I/O.
- The same connector-only dispatch, per-record grants and proposal review as the original core.
- Native lock events plus monotonic status epochs so a stale unlocked response cannot override a newer locked state.
- Windows executable/MCPB packaging source and current-user NSIS configuration. Legacy macOS integration is retained separately.

### What the new tests cover

The Linux suite adds a monitor-gate regression: when the atomic gate closes, tool access fails before the observer can acquire the service mutex; reopening the gate does not unlock the database. Status epochs advance on lock/unlock.

The five Windows-only tests passed on the Windows Server runner: real DPAPI roundtrip/tamper detection, on-disk DACL checks and overwrite refusal, a negative Everyone-ACE test, isolated Credential Manager entries/deletion, named-pipe request/duplicate-listener refusal, session-event classification, invalid-window owner-verification failure and SID checks. Fifteen core contract tests also passed against real Windows SQLCipher and the named-pipe RPC. None of those checks verifies the interactive Windows desktop or a live Claude app. No test substitutes fake Windows API success.

Production local RPC now requires a one-byte response acknowledgment after the client consumes and parses the complete response frame. The server retains its pipe handle until that acknowledgment or its transport deadline, but releases the service mutex first so revocation is not delayed by a slow client. This is an internal transport handshake, not a change to public MCP stdio. The Windows core pipe test uses production `call_pipe`/`serve_stream` without a test-only keepalive. Two additional Linux contracts verify delayed acknowledgment/revocation and absent-acknowledgment timeout on the same production server path; the normal socket contract exercises the production client's acknowledgment.

### Commands and boundaries

- Linux execution: CARGO_BUILD_JOBS=4 cargo test --manifest-path desktop/alexandria-vault/Cargo.toml -p alexandria-vault-core --locked -- --test-threads=2
- Windows API/test compiler check: cargo +1.88.0 check --manifest-path desktop/alexandria-vault/Cargo.toml -p alexandria-windows --tests --target x86_64-pc-windows-gnu
- Windows core/test/adapter and refreshed security-test compiler check: cargo +1.88.0 check --manifest-path desktop/alexandria-vault/Cargo.toml -p alexandria-vault-core -p alexandria-windows --tests --target x86_64-pc-windows-gnu --locked
- The second check used Zig cross-C/compiler and archiver wrappers for actual Windows-target bundled OpenSSL/SQLCipher. The wrappers normalize Cargo's target triple for Zig. This was not a substitution of Linux SQLite or a native Windows runtime.
- UI checks: pnpm --filter @workspace/alexandria-vault typecheck; pnpm --filter @workspace/alexandria-vault build
- Manifest: pnpm --filter @workspace/alexandria-vault exec mcpb validate mcpb/manifest.windows.json

Rust 1.88 checks the core/security modules. The locked Tauri dependency graph requires Rust 1.90 for a full native build; the Windows workflow and developer instructions use 1.90. A core-only check on 1.88 is not proof that the native app builds on that version.

The first cross-C attempt rejected Cargo's target spelling; normalizing the Zig wrapper resolved that tooling error and the actual Windows core check passed. A highly parallel initial Linux vendored-OpenSSL build timed out; the final bounded-parallelism build and all 19 tests completed successfully. A completion check exposed the original pipe-close delivery race; the production acknowledgment fix and regressions above replace that unsafe behavior. Neither preliminary failure is counted as a passing verification.

### Windows release gates still open

The installer, Claude MCPB and `SHA256SUMS.txt` are available as public release downloads above, without GitHub sign-in. The original [Actions artifact](https://github.com/alphablocks/alexandria/actions/runs/41286112047/artifacts/13075647555) remains separate and may require sign-in. The installer is unsigned; Windows may show a publisher/SmartScreen warning.

On a Windows 11 PC, verify actual Hello cancellation/approval and session-change races; inspect real ACLs and protected credential entries; exercise native CRUD/grants/review/import/export/backup/fresh restore; test screen lock, suspend/resume, idle and monitor failure; install the extension under permitted policy; and run actual Claude save/retrieve/revoke/lock flows. Cross-checking Rust source cannot verify any of those interactive behaviors.

Code signing, trustworthy distribution, hostile IPC/parser campaigns, another-OS-user access tests, cryptographic review and dependency redistribution notices remain release work. Do not bypass OS/organization protections or use irreplaceable sensitive data to compensate for missing verification.

## Historical baseline before the Windows port

The remaining sections record the earlier Linux/macOS-source baseline. Its original 16-test count and Mac-only release gate are historical, not the current target or the latest verification count.

## Delivered

- A real Rust/SQLCipher local store, not an unencrypted browser fallback.
- Restricted local service and four MCP tools with per-installation authentication, explicit record grants and owner-approved writes.
- Record editing/history, deletion, local keyword retrieval and bounded proposals.
- JSON/Markdown portability, validated atomic imports and age-encrypted snapshot recovery.
- React/Tauri management UI connected to native commands.
- macOS Keychain/screen-lock helper, native packaging configuration and Claude MCPB adapter source.
- Developer run/build, consent, recovery and limitation instructions in README.md.

## Executed checks

| Check | Actual outcome |
| --- | --- |
| Rust core contract suite | PASS — 16 tests, 0 failures |
| Rust workspace check with locked dependencies | PASS on Linux; macOS-specific modules are excluded, not verified |
| UI TypeScript check | PASS |
| UI production build | PASS |
| Rust formatting | Completed; sources parse |
| Git whitespace check | PASS |
| Existing public site | Still renders; source under artifacts/ and lib/ was not modified |

Commands executed:

- cargo test --manifest-path desktop/alexandria-vault/Cargo.toml -p alexandria-vault-core -- --test-threads=2
- cargo check --manifest-path desktop/alexandria-vault/Cargo.toml --workspace --locked
- pnpm --filter @workspace/alexandria-vault typecheck
- pnpm --filter @workspace/alexandria-vault build
- cargo fmt --manifest-path desktop/alexandria-vault/Cargo.toml --all
- git diff --check

The tests use generated ephemeral keys and synthetic records. They exercise actual SQLCipher databases and age files, force a real database lock to reject a write, and send real connector requests through Unix sockets. The stdio frame processor is the same function used by the packaged adapter. No Claude account, macOS Keychain or complete desktop window was exercised.

## Acceptance-case mapping

PASS below means the named service contract was exercised. PARTIAL means some assertions passed but the complete architecture case has not been verified. It is not a release sign-off.

| Case | Status | Evidence and limits |
| --- | --- | --- |
| V01 local operation | PARTIAL | Real local store works without accounts; packaged offline installation/network observation not performed |
| V02 scope isolation | PASS at core boundary | Disjoint grants, forbidden IDs, query isolation and private new records |
| V03 default-deny identity | PASS at core boundary | No initial grants, incorrect credential rejected; unknown caller fields cannot select owner identity |
| V04 proposal-only writes | PASS at core boundary | Read-only denial, pending approval and inability to invoke owner tools |
| V05 honest failure receipts | PASS for exercised failure | Real database lock causes storage failure, no partial record, later approval works; not a disk-full/crash-injection campaign |
| V06 stale versions | PASS at core boundary | Expected-version conflict, current record and prior history preserved |
| V07 revocation | PASS for local socket contract | Revocation/dispatch mutex exercised; fresh requests denied, pending approval canceled |
| V08 locking | PARTIAL | Manual/idle lock tested; macOS screen/suspend/Keychain behavior blocked |
| V09 unavailable service | PASS for socket contract | Absent listener returns UNAVAILABLE, not an empty successful search |
| V10 encryption | PARTIAL | Real SQLCipher, wrong-key denial and ciphertext sentinel check pass; native binary temp/journal inspection and deliberately substituted SQLite build remain unrun |
| V11 retention/logging | PARTIAL | Expired proposal text scrubbed, operation identity retained, seven-day audit cleanup tested; native crash/log capture not tested |
| V12 bad recovery inputs | PARTIAL | Invalid identity and tampered age backup rejected, staging cleaned; broad malformed-envelope fuzzing not performed |
| V13 clean restore | PASS at core content boundary | Exact content restored into a new keyed store without old connections/proposals; native fresh-machine workflow blocked |
| V14 key loss | PARTIAL | Wrong identity fails and valid identity restores; real lost-device/native recovery exercise blocked |
| V15 deletion | PASS for logical live-store contract | Versions, linked pending content and active retrieval disappear; no forensic SSD/backup erasure claim |
| V16 portability | PASS for fixture contract | Required record fields, statuses/history, readable Markdown, duplicate import and atomic conflict rejection |
| V17 untrusted content | PARTIAL | Service rejects owner operations from connectors and withholds proposed inference; model-answer compliance not tested |
| V18 grant snapshots | PARTIAL | New records remain private and edits retain version controls; native recipient-warning UI not run |
| V19 resource bounds | PARTIAL | Pending-proposal, text and frame limits tested; large-scale load/parallel fuzzing and every numeric ceiling not tested |
| V20 socket identity | PARTIAL | Real same-user socket, token checks and revocation tested; another OS-user access attempt not executed |
| V21 Claude Desktop | BLOCKED | Needs target Mac, compiled helper/adapter, permitted extension install and authorized Claude session |
| V22 ChatGPT tunnel | OUT OF SCOPE / NOT RUN | No tunnel provisioned or credentials requested |
| V23 remote failures | OUT OF SCOPE / NOT RUN | No remote bridge exists in this prototype |
| V24 native UI isolation | BLOCKED for runtime | Restrictive CSP/capabilities and escaped UI text implemented; native renderer/IPC attack tests not run |

## Not delivered as verified

No signed/notarized Mac installer, successful Mac compilation, observed Keychain prompt, screen-lock guarantee, interactive native UI test or live Claude retrieval. Native source is implemented but can still have platform-specific compile/runtime issues. A Linux workspace check does not compile those modules.

No ChatGPT connection, remote Claude endpoint, hosted vault, cloud synchronization or universal one-click install. No market-demand or comparative product result. No cryptographic audit or complete dependency redistribution/license review.

## Next required gate

The current next gate is interactive Windows 11 runtime verification and the security/distribution work above. The Windows build and public-download checks passed. Mac runtime remains a separate, unverified legacy path.

The website now explains and links to the desktop vault downloads. It is not the vault itself: records, keys and native controls remain in the separate desktop application at desktop/alexandria-vault/.
