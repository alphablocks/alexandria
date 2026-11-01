# Alexandria

**Local-first memory for Claude Desktop. Your context, under your control.**

Stop repeating the same background in every AI conversation. Alexandria is a desktop vault for the preferences, project context and decisions you choose to keep. Connect it to Claude Desktop through MCP, and decide exactly which records Claude can retrieve.

No new chat interface. No Alexandria account. No hosted memory database.

> **Experimental, unsigned prototype.** The Windows build and automated tests pass, but installation, Windows Hello, session-lock/recovery flows and live Claude pairing have **not been verified interactively**. Try it with non-sensitive sample data, not irreplaceable personal information. This is not an audited or production-ready security product.

## Download for Windows

**[Download the Windows x64 installer](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/Alexandria-Windows-x64-setup.exe)**

| File | What it does |
| --- | --- |
| [Windows installer](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/Alexandria-Windows-x64-setup.exe) | Installs the Alexandria desktop vault for the current Windows user. |
| [Claude extension — `.mcpb`](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/Alexandria-Windows.mcpb) | Connects Claude Desktop to your local vault. Install the desktop app first. |
| [SHA-256 checksums](https://github.com/alphablocks/alexandria/releases/download/windows-prototype-0.1.0/SHA256SUMS.txt) | Lets you check that your downloads match the published files. |

**Version:** 0.1.0 prototype · **Platform:** Windows 11 x64 · **License:** MIT

These public downloads do not require GitHub sign-in. See the [release notes](https://github.com/alphablocks/alexandria/releases/tag/windows-prototype-0.1.0) for build provenance and limitations.

The installer is **unsigned**. Windows or your organization may warn about or block it. Do not disable or bypass security controls to install it.

## Why use it?

- **Repeat less.** Keep selected background available to Claude across conversations instead of pasting it again.
- **Choose what is shared.** Each connection gets access only to the records you grant it. New records are not shared automatically.
- **Stay in control of saves.** If you enable proposals, Claude can propose new records; you approve them in Alexandria before they are saved.
- **Keep a way out.** Export records as JSON or Markdown, and create encrypted recovery backups to move or restore your context.

For example, you might save your preferred writing style, the background of a project, or a decision you want later conversations to respect. You choose the records; Alexandria does not automatically import your chat history.

## Before you start

You need:

- **Windows 11 x64**, with Windows Hello configured using a PIN, face or fingerprint.
- An interactive Windows user session and a local NTFS storage location.
- **Claude Desktop**, with custom local extensions permitted by your account and organization.

There is no packaged macOS or Linux release. ChatGPT and other assistant connections are not implemented in this prototype.

## Set up Alexandria with Claude

1. **Install and open Alexandria.** Download the Windows installer above. Respect any Windows or organization restrictions.
2. **Create your vault.** Approve the Windows Hello prompt, then add a non-sensitive test record.
3. **Create a connection.** In **Connections**, grant access to that test record. Leave save proposals disabled until you want to test them.
4. **Install the Claude extension.** In Claude Desktop's settings, open Extensions and install the downloaded `.mcpb` as a custom extension. Enter the connection's **non-secret connection ID** when requested.
5. **Keep Alexandria open and unlocked.** Ask Claude to use the Alexandria tools to search for your test record. Verify the result rather than assuming the connection works.
6. **Check your controls.** Revoke the grant or lock Alexandria and confirm the record is no longer accessible through the connection.

The connection ID is not a vault key. The adapter uses its separate connector credential from Windows Credential Manager; it cannot unlock the vault for you.

## What stays local—and what does not

| Boundary | Behavior |
| --- | --- |
| Stored memory | Your vault is a local SQLCipher-encrypted database. Alexandria does not upload it to a hosted vault or synchronize it to the cloud. |
| Access | Claude can retrieve only records granted to its connection, while the vault is running and unlocked. |
| Model processing | **When Claude retrieves a record, that content leaves your computer and is processed under the assistant provider's policies.** Local storage does not mean local inference. |
| Saves | Connector proposals require your approval. Alexandria does not silently ingest your entire conversations. |
| Portability | Explicit exports and encrypted recovery backups let you move context. This is not automatic cross-assistant synchronization. |

Encryption and Windows Hello are not protection against every threat. A compromised unlocked operating system, an administrator or another process running as the same user is outside this prototype's protection. Read the [security and verification boundaries](desktop/alexandria-vault/VERIFICATION.md) before experimenting.

## What has actually been checked?

- A real Windows/MSVC build produced the current-user NSIS installer.
- **15 core contract tests and 5 Windows security tests** passed on a Windows Server 2022 runner.
- The Claude MCPB package was built and validated.
- Publication checked the original build hashes and included executables.
- The public files were downloaded without credentials and independently matched against the published SHA-256 manifest.

**Not yet checked interactively:** installation on a Windows 11 PC, native Hello prompts, screen-lock/suspend behavior, recovery dialogs and live Claude use. Passing CI does not prove those user journeys work.

[Windows build](https://github.com/alphablocks/alexandria/actions/runs/41286112047) · [Download publication](https://github.com/alphablocks/alexandria/actions/runs/41288451556) · [Full verification record](desktop/alexandria-vault/VERIFICATION.md)

## Build, inspect or contribute

See the [desktop developer guide](desktop/alexandria-vault/README.md) for architecture, prerequisites, tests and source-build instructions. The project uses Rust, SQLCipher, Tauri and a React management interface.

This repository contains the desktop source and required build inputs—not the website, workspace history, personal vaults, credentials or unrelated attachments. The example context pack is a synthetic test fixture.

Bug reports should describe the platform, release and reproduction steps. **Do not post vault contents, recovery identities, connector credentials or other secrets.**

## License

The Alexandria code is [MIT licensed](LICENSE). Dependencies retain their own license terms. The prototype's security and dependency-redistribution review is not complete.
