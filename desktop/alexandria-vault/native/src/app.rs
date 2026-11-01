use crate::platform::Platform;
use alexandria_vault_core::{model::*, portability, service::Service};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tauri::{Manager, State};
use zeroize::Zeroizing;

type Pending = Arc<Mutex<Option<(Pack, bool, std::time::Instant)>>>;
#[derive(Clone)]
struct Native {
    service: Arc<Mutex<Service>>,
    dir: PathBuf,
    platform: Platform,
    pending: Pending,
    monitor: Arc<AtomicBool>,
}
fn bytes_key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let decoded = Zeroizing::new(hex::decode(bytes).map_err(|_| Error("KEYCHAIN_ERROR"))?);
    require(decoded.len() == 32, "KEYCHAIN_ERROR")?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    // Never follow symlinks or silently overwrite existing files.
    let mut file = alexandria_vault_core::private_fs::create_private(path)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}
fn read_bounded(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    require(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "INVALID_INPUT",
    )?;
    require(std::fs::metadata(path)?.len() <= limit, "LIMIT_EXCEEDED")?;
    let mut data = Zeroizing::new(vec![]);
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut data)?;
    require(data.len() as u64 <= limit, "LIMIT_EXCEEDED")?;
    Ok(data)
}
fn save_dialog(name: &str, title: &str) -> Result<PathBuf> {
    rfd::FileDialog::new()
        .set_file_name(name)
        .set_title(title)
        .save_file()
        .ok_or(Error("CANCELLED"))
}
fn open_dialog(title: &str) -> Result<PathBuf> {
    rfd::FileDialog::new()
        .set_title(title)
        .pick_file()
        .ok_or(Error("CANCELLED"))
}
fn owner(state: &Native, action: &str, payload: &Value) -> Result<Value> {
    if action == "status" {
        let mut service = state.service.lock().map_err(|_| Error("SERVICE_ERROR"))?;
        let status = service.status();
        if status["unlocked"] != true {
            let mut pending = state.pending.lock().map_err(|_| Error("SERVICE_ERROR"))?;
            // Recovery previews are allowed before creating a vault. Normal
            // import previews must disappear when an existing vault is locked.
            if pending
                .as_ref()
                .is_some_and(|(_, restore, at)| !restore || at.elapsed().as_secs() >= 900)
            {
                *pending = None;
            }
        }
        return Ok(status);
    }
    if action == "create" || action == "unlock" {
        require(
            state.monitor.load(Ordering::SeqCst),
            "LOCK_MONITOR_UNAVAILABLE",
        )?;
        let mut service = state.service.lock().map_err(|_| Error("SERVICE_ERROR"))?;
        let creating = action == "create";
        require(
            !creating || service.status()["initialized"] == false,
            "ALREADY_EXISTS",
        )?;
        let key = if creating {
            let key = random_key();
            let hex = Zeroizing::new(hex::encode(key.as_slice()));
            state
                .platform
                .secret("set-vault", None, Some(hex.as_bytes()))?;
            if let Err(e) = state.platform.secret("get-vault", None, None) {
                let _ = state.platform.secret("delete-vault", None, None);
                return Err(e);
            }
            key
        } else {
            bytes_key(&state.platform.secret("get-vault", None, None)?)?
        };
        let result = service.unlock(&key, creating);
        if result.is_err() && creating {
            // Remove only the key we just installed if initialization failed.
            let _ = state.platform.secret("delete-vault", None, None);
            let _ = std::fs::remove_file(state.dir.join("vault.db"));
        }
        return result;
    }
    if action == "pair" {
        let mut service = state.service.lock().map_err(|_| Error("SERVICE_ERROR"))?;
        let store = service.store()?;
        let label = string(payload, "label")?;
        let (cid, token) = store.pair(label)?;
        if let Err(e) = state
            .platform
            .secret("set-connector", Some(&cid), Some(token.as_bytes()))
        {
            let _ = store.revoke(&cid);
            return Err(e);
        }
        return Ok(json!({"id":cid,"label":label}));
    }
    if action == "export_dialog" {
        let pack = state
            .service
            .lock()
            .map_err(|_| Error("SERVICE_ERROR"))?
            .store()?
            .export(None)?;
        let path = save_dialog(
            "alexandria-context.json",
            "Export PLAINTEXT context — keep these files private",
        )?;
        let markdown_path = path.with_extension("md");
        require(!path.exists() && !markdown_path.exists(), "FILE_EXISTS")?;
        state
            .service
            .lock()
            .map_err(|_| Error("SERVICE_ERROR"))?
            .store()?;
        // Compact output keeps the vault's enforced portable-size budget.
        let raw = Zeroizing::new(serde_json::to_vec(&pack)?);
        write_private(&path, &raw)?;
        if let Err(e) = write_private(&markdown_path, portability::markdown(&pack).as_bytes()) {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        return Ok(json!({"status":"OK"}));
    }
    if action == "import_dialog" || action == "restore_dialog" {
        let restoring = action == "restore_dialog";
        let pack = if restoring {
            require(
                state
                    .service
                    .lock()
                    .map_err(|_| Error("SERVICE_ERROR"))?
                    .status()["initialized"]
                    == false,
                "RESTORE_REQUIRES_NEW_VAULT",
            )?;
            let backup = read_bounded(
                &open_dialog("Choose encrypted .age recovery backup")?,
                150 * 1024 * 1024,
            )?;
            let key = read_bounded(&open_dialog("Choose its separate recovery identity")?, 4096)?;
            portability::recover_pack(
                &backup,
                std::str::from_utf8(&key).map_err(|_| Error("INVALID_RECOVERY_KEY"))?,
                &state.dir,
            )?
        } else {
            // Refuse even opening/importing when locked.
            state
                .service
                .lock()
                .map_err(|_| Error("SERVICE_ERROR"))?
                .store()?;
            let bytes = read_bounded(
                &open_dialog("Choose Alexandria context JSON")?,
                50 * 1024 * 1024,
            )?;
            portability::parse_pack(&bytes)?
        };
        let preview = if restoring {
            json!({"records":pack.records.len(),"added":pack.records.len(),"duplicates":0,"conflicts":[],"restore":true})
        } else {
            state
                .service
                .lock()
                .map_err(|_| Error("SERVICE_ERROR"))?
                .store()?
                .preview_import(&pack)?
        };
        *state.pending.lock().map_err(|_| Error("SERVICE_ERROR"))? =
            Some((pack, restoring, std::time::Instant::now()));
        return Ok(preview);
    }
    if action == "import_cancel" {
        *state.pending.lock().map_err(|_| Error("SERVICE_ERROR"))? = None;
        return Ok(json!({"status":"OK"}));
    }
    if action == "import_confirm" || action == "restore_confirm" {
        let (pack, restoring, prepared_at) = state
            .pending
            .lock()
            .map_err(|_| Error("SERVICE_ERROR"))?
            .take()
            .ok_or(Error("NO_PENDING_IMPORT"))?;
        require(prepared_at.elapsed().as_secs() < 900, "NO_PENDING_IMPORT")?;
        require(restoring == (action == "restore_confirm"), "INVALID_INPUT")?;
        if restoring {
            require(
                state.monitor.load(Ordering::SeqCst),
                "LOCK_MONITOR_UNAVAILABLE",
            )?;
            require(
                state
                    .service
                    .lock()
                    .map_err(|_| Error("SERVICE_ERROR"))?
                    .status()["initialized"]
                    == false,
                "ALREADY_EXISTS",
            )?;
            // Use a new key and a staging file. Old grants/credentials/proposals
            // never enter this new operational vault.
            let key = random_key();
            let staging = state.dir.join(format!(".new-{}", id()));
            let result = (|| {
                let mut store = alexandria_vault_core::Store::open(&staging, &key, true)?;
                store.import(&pack)?;
                drop(store);
                // Serialize the fresh-vault commit and authentication with
                // create/unlock. Lock events still close the atomic gate first.
                let mut live = state.service.lock().map_err(|_| Error("SERVICE_ERROR"))?;
                require(live.status()["initialized"] == false, "ALREADY_EXISTS")?;
                state.platform.secret(
                    "set-vault",
                    None,
                    Some(Zeroizing::new(hex::encode(key.as_slice())).as_bytes()),
                )?;
                if let Err(e) = state.platform.secret("get-vault", None, None) {
                    let _ = state.platform.secret("delete-vault", None, None);
                    return Err(e);
                }
                if let Err(e) = std::fs::rename(&staging, state.dir.join("vault.db")) {
                    let _ = state.platform.secret("delete-vault", None, None);
                    return Err(e.into());
                }
                let result = live.unlock(&key, false);
                if result.is_err() {
                    let _ = state.platform.secret("delete-vault", None, None);
                    let _ = std::fs::remove_file(state.dir.join("vault.db"));
                }
                result
            })();
            let _ = std::fs::remove_file(&staging);
            return result;
        }
        return state
            .service
            .lock()
            .map_err(|_| Error("SERVICE_ERROR"))?
            .store()?
            .import(&pack);
    }
    if action == "backup_dialog" {
        let (encrypted, identity) = state
            .service
            .lock()
            .map_err(|_| Error("SERVICE_ERROR"))?
            .store()?
            .encrypted_backup()?;
        let key_path = save_dialog(
            "alexandria-recovery-key.txt",
            "Save SECRET recovery key separately from the backup",
        )?;
        let backup_path = save_dialog(
            "alexandria-backup.age",
            "Save encrypted backup — keep the recovery key elsewhere",
        )?;
        require(
            key_path != backup_path && !key_path.exists() && !backup_path.exists(),
            "FILE_EXISTS",
        )?;
        state
            .service
            .lock()
            .map_err(|_| Error("SERVICE_ERROR"))?
            .store()?;
        write_private(&key_path, identity.as_bytes())?;
        if let Err(e) = write_private(&backup_path, &encrypted) {
            let _ = std::fs::remove_file(&key_path);
            return Err(e);
        }
        return Ok(json!({"status":"OK"}));
    }
    if action == "lock" {
        *state.pending.lock().map_err(|_| Error("SERVICE_ERROR"))? = None;
    }
    let result = state
        .service
        .lock()
        .map_err(|_| Error("SERVICE_ERROR"))?
        .owner(action, payload)?;
    if action == "revoke" {
        let _ = state
            .platform
            .secret("delete-connector", Some(string(payload, "id")?), None);
    }
    Ok(result)
}
#[tauri::command]
#[cfg(target_os = "macos")]
fn vault_command(
    action: String,
    payload: Value,
    state: State<'_, Native>,
) -> std::result::Result<Value, String> {
    owner(&state, &action, &payload).map_err(|e| e.0.into())
}
#[cfg(windows)]
#[tauri::command]
async fn vault_command(
    action: String,
    payload: Value,
    state: State<'_, Native>,
) -> std::result::Result<Value, String> {
    let native = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        owner(&native, &action, &payload).map_err(|e| e.0.to_string())
    })
    .await
    .map_err(|_| "SERVICE_ERROR".to_string())?
}
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = Platform::data_dir()?;
            let monitor = Arc::new(AtomicBool::new(false));
            let service = Arc::new(Mutex::new(Service::with_gate(
                &dir.join("vault.db"),
                monitor.clone(),
            )));
            let platform = Platform::new(app.handle(), &dir, monitor.clone())?;
            let pending: Pending = Arc::new(Mutex::new(None));
            let locking = service.clone();
            let clearing = pending.clone();
            let handle = app.handle().clone();
            let on_lock: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                let status = if let Ok(mut s) = locking.lock() {
                    s.lock();
                    Some(s.status())
                } else {
                    None
                };
                if let Ok(mut p) = clearing.lock() {
                    *p = None;
                }
                use tauri::Emitter;
                let _ = handle.emit("vault-locked", status);
            });
            platform.start_transport(service.clone(), monitor.clone(), on_lock.clone())?;
            platform.start_monitor(on_lock);
            let expiry = service.clone();
            let pending_expiry = pending.clone();
            let notifier = app.handle().clone();
            std::thread::spawn(move || {
                let mut was_open = false;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let status = expiry.lock().ok().map(|mut s| s.status());
                    let open = status.as_ref().is_some_and(|s| s["unlocked"] == true);
                    if was_open && !open {
                        if let Ok(mut p) = pending_expiry.lock() {
                            *p = None;
                        }
                        use tauri::Emitter;
                        let _ = notifier.emit("vault-locked", status);
                    }
                    was_open = open;
                    if let Ok(mut p) = pending_expiry.lock() {
                        if p.as_ref()
                            .is_some_and(|(_, _, at)| at.elapsed().as_secs() >= 900)
                        {
                            *p = None;
                        }
                    }
                }
            });
            app.manage(Native {
                service,
                dir,
                platform,
                pending,
                monitor,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![vault_command])
        .build(tauri::generate_context!())
        .expect("Alexandria could not start its native security services.")
        .run(|handle, event| {
            if matches!(
                event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ) {
                let state = handle.state::<Native>();
                if let Ok(mut service) = state.service.lock() {
                    service.lock();
                };
            }
        });
}
