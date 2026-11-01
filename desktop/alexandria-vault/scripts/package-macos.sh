#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Requires Apple Silicon macOS."; exit 1; }
command -v swiftc >/dev/null
mkdir -p native/binaries mcpb/server
swiftc native/keychain.swift -o native/binaries/alexandria-keychain-aarch64-apple-darwin -framework Security -framework AppKit
cargo build --release -p alexandria-vault-core --bin alexandria-mcp
cp target/release/alexandria-mcp mcpb/server/alexandria-mcp
cp native/binaries/alexandria-keychain-aarch64-apple-darwin mcpb/server/alexandria-keychain
echo "Native helper and adapter built. Run pnpm desktop:build and the documented MCPB pack command."
