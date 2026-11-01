use alexandria_vault_core::{model::*, rpc, Service};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct Platform {
    helper: PathBuf,
    dir: PathBuf,
    epoch: Arc<AtomicU64>,
    ready: Arc<AtomicBool>,
}
impl Platform {
    pub fn data_dir() -> Result<PathBuf> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let dir = PathBuf::from(std::env::var_os("HOME").ok_or(Error("IO_ERROR"))?)
            .join("Library/Application Support/org.alexandria.vault");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        require(
            !std::fs::symlink_metadata(&dir)?.file_type().is_symlink(),
            "UNSAFE_PATH",
        )?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }
    pub fn new(_: &tauri::AppHandle, dir: &Path, ready: Arc<AtomicBool>) -> Result<Self> {
        let mut helper = std::env::current_exe()?
            .parent()
            .ok_or(Error("IO_ERROR"))?
            .join("alexandria-keychain");
        #[cfg(debug_assertions)]
        if !helper.is_file() {
            helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("binaries/alexandria-keychain-aarch64-apple-darwin");
        }
        require(helper.is_file(), "KEYCHAIN_HELPER_UNAVAILABLE")?;
        Ok(Self {
            helper,
            dir: dir.into(),
            ready,
            epoch: Arc::new(AtomicU64::new(0)),
        })
    }
    pub fn secret(
        &self,
        action: &str,
        account: Option<&str>,
        input: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        let mut cmd = Command::new(&self.helper);
        cmd.arg(action);
        if let Some(a) = account {
            cmd.arg(a);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error("KEYCHAIN_ERROR"))?;
        if let Some(bytes) = input {
            child
                .stdin
                .take()
                .ok_or(Error("KEYCHAIN_ERROR"))?
                .write_all(bytes)?;
        } else {
            drop(child.stdin.take());
        }
        let output = child.wait_with_output()?;
        require(output.status.success(), "KEYCHAIN_ERROR")?;
        if action == "get-vault" {
            require(
                self.ready.load(Ordering::SeqCst) && self.epoch.load(Ordering::SeqCst) == epoch,
                "KEYCHAIN_ERROR",
            )?;
        }
        Ok(Zeroizing::new(output.stdout))
    }
    pub fn start_monitor(&self, on_lock: Arc<dyn Fn() + Send + Sync>) {
        let this = self.clone();
        std::thread::spawn(move || {
            if let Ok(mut child) = Command::new(&this.helper)
                .arg("watch")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                if let Some(stdout) = child.stdout.take() {
                    for line in BufReader::new(stdout).lines() {
                        match line.as_deref() {
                            Ok("READY") => this.ready.store(true, Ordering::SeqCst),
                            Ok("LOCK") => {
                                this.ready.store(false, Ordering::SeqCst);
                                this.epoch.fetch_add(1, Ordering::SeqCst);
                                on_lock();
                                this.ready.store(true, Ordering::SeqCst);
                            }
                            _ => break,
                        }
                    }
                }
                let _ = child.kill();
                let _ = child.wait();
            }
            this.ready.store(false, Ordering::SeqCst);
            this.epoch.fetch_add(1, Ordering::SeqCst);
            on_lock();
        });
    }
    pub fn start_transport(
        &self,
        service: Arc<Mutex<Service>>,
        ready: Arc<AtomicBool>,
        on_lock: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<()> {
        use std::os::unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        };
        let socket = self.dir.join("vault.sock");
        require(UnixStream::connect(&socket).is_err(), "ALREADY_RUNNING")?;
        if socket.exists() {
            std::fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(s) = stream {
                    let _ = rpc::serve_connection(s, &service);
                } else {
                    break;
                }
            }
            ready.store(false, Ordering::SeqCst);
            on_lock();
        });
        Ok(())
    }
}
