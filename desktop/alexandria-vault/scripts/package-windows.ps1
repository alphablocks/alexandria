param([switch]$PackExtension)
$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Run on Windows with the MSVC Rust toolchain." }
$Vault = (Resolve-Path "$PSScriptRoot/..").Path
$Repo = (Resolve-Path "$Vault/../..").Path
$HostTriple = (& rustc -vV | Select-String "^host: ").ToString().Substring(6).Trim()
if ($LASTEXITCODE -ne 0 -or $HostTriple -ne "x86_64-pc-windows-msvc") {
  throw "This first Windows package targets x64 MSVC. Other architectures are not release-verified."
}
& cargo build --manifest-path "$Vault/Cargo.toml" --release --locked -p alexandria-vault-core --bin alexandria-mcp
if ($LASTEXITCODE -ne 0) { throw "Adapter build failed; no extension is ready." }
$Staging = Join-Path $Repo "generated-artifacts/alexandria-windows-extension"
New-Item -ItemType Directory -Force "$Staging/server" | Out-Null
Copy-Item "$Vault/target/release/alexandria-mcp.exe" "$Staging/server/alexandria-mcp.exe" -Force
Copy-Item "$Vault/mcpb/manifest.windows.json" "$Staging/manifest.json" -Force
if ($PackExtension) {
  & pnpm --filter "@workspace/alexandria-vault" exec mcpb validate "$Staging/manifest.json"
  if ($LASTEXITCODE -ne 0) { throw "MCPB validation failed." }
  & pnpm --filter "@workspace/alexandria-vault" exec mcpb pack "$Staging" "$Repo/generated-artifacts/Alexandria-Windows.mcpb"
  if ($LASTEXITCODE -ne 0) { throw "MCPB packing failed." }
}
Write-Host "Windows adapter built. Staging: $Staging"
Write-Host "Build the desktop installer separately with: pnpm --filter @workspace/alexandria-vault desktop:build"
