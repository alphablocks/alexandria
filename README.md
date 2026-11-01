# Alexandria local memory vault

MIT-licensed, build-only source snapshot. Windows 11 x64 / Windows Hello.

See [the desktop guide](desktop/alexandria-vault/README.md) and [actual verification boundaries](desktop/alexandria-vault/VERIFICATION.md).

This repository excludes the dataset website, workspace history, personal memories, credentials and unrelated attachments. The synthetic context pack is a test fixture. Desktop package catalog references are resolved to explicit dependency versions; the build workspace has its own frozen lock.

Actions produces UNSIGNED experimental artifacts, not a signed public release. Unattended CI cannot verify Windows Hello, session/suspend behavior, native dialogs, recovery or live Claude use. Do not bypass OS or organization policy.
