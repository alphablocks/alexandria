use alexandria_vault_core::{
    model::*,
    rpc,
    windows::{
        self, credentials,
        monitor::{self, Signals},
    },
    Service,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tauri::Manager;
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct Platform {
    dir: PathBuf,
    hwnd: isize,
    signals: Signals,
}
impl Platform {
    pub fn data_dir() -> Result<PathBuf> {
        Ok(windows::fs::data_dir()?)
    }
    pub fn new(app: &tauri::AppHandle, dir: &Path, ready: Arc<AtomicBool>) -> Result<Self> {
        let window = app
            .get_webview_window("main")
            .ok_or(Error("OWNER_VERIFICATION_UNAVAILABLE"))?;
        let hwnd = window
            .hwnd()
            .map_err(|_| Error("OWNER_VERIFICATION_UNAVAILABLE"))?
            .0 as isize;
        Ok(Self {
            dir: dir.into(),
            hwnd,
            signals: Signals::new(ready),
        })
    }
    pub fn secret(
        &self,
        action: &str,
        account: Option<&str>,
        input: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.dir.join("vault-key.dpapi");
        match action {
            "set-vault" => credentials::save_vault(&path, input.ok_or(Error("INVALID_INPUT"))?)?,
            "get-vault" => {
                require(
                    self.signals.ready.load(Ordering::SeqCst),
                    "LOCK_MONITOR_UNAVAILABLE",
                )?;
                let epoch = self.signals.epoch.load(Ordering::SeqCst);
                windows::hello::verify_owner(self.hwnd)?;
                require(
                    self.signals.ready.load(Ordering::SeqCst)
                        && epoch == self.signals.epoch.load(Ordering::SeqCst),
                    "OWNER_VERIFICATION_DENIED",
                )?;
                return Ok(credentials::load_vault(&path)?);
            }
            "delete-vault" => std::fs::remove_file(path)?,
            "set-connector" => credentials::set_connector(
                account.ok_or(Error("INVALID_INPUT"))?,
                input.ok_or(Error("INVALID_INPUT"))?,
            )?,
            "get-connector" => {
                return Ok(credentials::connector(
                    account.ok_or(Error("INVALID_INPUT"))?,
                )?)
            }
            "delete-connector" => {
                credentials::delete_connector(account.ok_or(Error("INVALID_INPUT"))?)?
            }
            _ => return Err(Error("DENIED")),
        }
        Ok(Zeroizing::new(vec![]))
    }
    pub fn start_monitor(&self, on_lock: Arc<dyn Fn() + Send + Sync>) {
        monitor::start(self.signals.clone(), on_lock);
    }
    pub fn start_transport(
        &self,
        service: Arc<Mutex<Service>>,
        ready: Arc<AtomicBool>,
        on_lock: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<()> {
        let mut listener = windows::pipe::Listener::bind()?;
        std::thread::spawn(move || {
            while let Ok(mut pipe) = listener.accept() {
                let _ = rpc::serve_stream(&mut pipe, &service);
            }
            ready.store(false, Ordering::SeqCst);
            on_lock();
        });
        Ok(())
    }
}
