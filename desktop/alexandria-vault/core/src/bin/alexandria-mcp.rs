use alexandria_vault_core::model::*;
#[cfg(any(target_os = "macos", windows))]
use alexandria_vault_core::rpc;
#[cfg(any(target_os = "macos", windows))]
use std::io::BufReader;
fn main() {
    if run().is_err() {
        eprintln!("Alexandria adapter unavailable. Open and unlock the native app, then check this installation's pairing.");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    require(
        args.len() == 3 && args[1] == "--connection",
        "INVALID_INPUT",
    )?;
    validate_text(&args[2], 128)?;
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        return Err(Error("UNSUPPORTED_PLATFORM"));
    }
    #[cfg(windows)]
    {
        // Separate per-installation Credential Manager entry; no vault-key access.
        let token = alexandria_vault_core::windows::credentials::connector(&args[2])?;
        let token = std::str::from_utf8(&token).map_err(|_| Error("DENIED"))?;
        rpc::run_stdio(
            BufReader::new(std::io::stdin().lock()),
            std::io::stdout().lock(),
            |tool, p| rpc::call_pipe(&args[2], token, tool, p),
        )
    }
    #[cfg(target_os = "macos")]
    {
        // The native helper obtains this adapter's credential from Keychain.
        // No vault key, environment secret, command-line token or config token.
        let helper = std::env::current_exe()?
            .parent()
            .ok_or(Error("IO_ERROR"))?
            .join("alexandria-keychain");
        let output = std::process::Command::new(helper)
            .args(["get-connector", &args[2]])
            .output()?;
        require(output.status.success(), "DENIED")?;
        let token =
            zeroize::Zeroizing::new(String::from_utf8(output.stdout).map_err(|_| Error("DENIED"))?);
        let home = std::env::var_os("HOME").ok_or(Error("IO_ERROR"))?;
        let socket = std::path::PathBuf::from(home)
            .join("Library/Application Support/org.alexandria.vault/vault.sock");
        rpc::run_stdio(
            BufReader::new(std::io::stdin().lock()),
            std::io::stdout().lock(),
            |tool, p| rpc::call_socket(&socket, &args[2], token.trim(), tool, p),
        )
    }
}
