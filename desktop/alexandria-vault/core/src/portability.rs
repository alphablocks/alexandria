use crate::{
    model::*,
    store::{read_records, Store},
};
use rusqlite::params;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const PACK_LIMIT: usize = 50 * 1024 * 1024;
const SNAPSHOT_LIMIT: u64 = 64 * 1024 * 1024;

pub fn parse_pack(bytes: &[u8]) -> Result<Pack> {
    require(bytes.len() <= PACK_LIMIT, "LIMIT_EXCEEDED")?;
    let pack: Pack = serde_json::from_slice(bytes)?;
    require(
        pack.format == "alexandria-context" && pack.schema_version == 1,
        "UNSUPPORTED_VERSION",
    )?;
    require(pack.records.len() <= 50_000, "LIMIT_EXCEEDED")?;
    let mut versions = HashMap::new();
    let mut by_id: HashMap<&str, Vec<&Record>> = HashMap::new();
    for r in &pack.records {
        validate_record(r)?;
        require(pack.export_scope.contains(&r.scope), "INVALID_INPUT")?;
        require(
            versions.insert((r.id.clone(), r.version), r).is_none(),
            "CONFLICT",
        )?;
        by_id.entry(&r.id).or_default().push(r);
    }
    require(by_id.len() <= 10_000, "LIMIT_EXCEEDED")?;
    for items in by_id.values_mut() {
        items.sort_by_key(|r| r.version);
        for (i, r) in items.iter().enumerate() {
            require(r.version == (i + 1) as i64, "BROKEN_VERSION_CHAIN")?;
            if i == 0 {
                require(r.supersedes.is_none(), "BROKEN_VERSION_CHAIN")?;
            } else {
                let prev = r.supersedes.as_ref().ok_or(Error("BROKEN_VERSION_CHAIN"))?;
                require(
                    prev.id == r.id && prev.version == r.version - 1,
                    "BROKEN_VERSION_CHAIN",
                )?;
                require(items[i - 1].status == "superseded", "BROKEN_VERSION_CHAIN")?;
                require(items[i - 1].scope == r.scope, "BROKEN_VERSION_CHAIN")?;
            }
            if i + 1 < items.len() {
                require(r.status == "superseded", "BROKEN_VERSION_CHAIN")?;
            } else {
                require(r.status != "superseded", "BROKEN_VERSION_CHAIN")?;
            }
        }
    }
    Ok(pack)
}

impl Store {
    pub fn export(&self, selected: Option<&[String]>) -> Result<Pack> {
        let mut records =
            read_records(&self.db, "SELECT data FROM records ORDER BY id,version", [])?;
        if let Some(ids) = selected {
            records.retain(|r| ids.contains(&r.id));
        }
        let scopes: std::collections::BTreeSet<_> =
            records.iter().map(|r| r.scope.clone()).collect();
        Ok(Pack {
            format: "alexandria-context".into(),
            schema_version: 1,
            synthetic: false,
            exported_at: now(),
            export_scope: scopes.into_iter().collect(),
            exclusions: vec![
                "deleted records".into(),
                "access grants".into(),
                "credentials".into(),
                "operational keys".into(),
            ],
            records,
        })
    }
    pub fn preview_import(&self, pack: &Pack) -> Result<Value> {
        let canonical = serde_json::to_vec(pack)?;
        parse_pack(&canonical)?;
        let mut added = 0;
        let mut duplicates = 0;
        let mut conflicts = vec![];
        let existing = read_records(&self.db, "SELECT data FROM records", [])?;
        let mut union: HashSet<String> = existing.iter().map(|r| r.id.clone()).collect();
        for r in &pack.records {
            union.insert(r.id.clone());
            if let Some(old) = existing
                .iter()
                .find(|old| old.id == r.id && old.version == r.version)
            {
                if old == r {
                    duplicates += 1;
                } else {
                    conflicts.push(format!("{} version {}", r.id, r.version));
                }
            } else if existing.iter().any(|old| old.id == r.id) {
                // No silent merges into live history or existing shared records.
                conflicts.push(format!(
                    "{} has existing history; resolve outside import",
                    r.id
                ));
            } else {
                added += 1;
            }
        }
        require(union.len() <= 10_000, "LIMIT_EXCEEDED")?;
        let mut total_versions = existing.len();
        let mut total_bytes = existing
            .iter()
            .map(|r| serde_json::to_vec(r).map(|v| v.len()))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<usize>();
        for r in &pack.records {
            if !existing
                .iter()
                .any(|old| old.id == r.id && old.version == r.version)
            {
                total_versions += 1;
                total_bytes += serde_json::to_vec(r)?.len();
            }
        }
        require(
            total_versions <= 50_000 && total_bytes <= 48 * 1024 * 1024,
            "LIMIT_EXCEEDED",
        )?;
        Ok(
            json!({"records":pack.records.len(),"added":added,"duplicates":duplicates,"conflicts":conflicts}),
        )
    }
    pub fn import(&mut self, pack: &Pack) -> Result<Value> {
        let preview = self.preview_import(pack)?;
        require(
            preview["conflicts"]
                .as_array()
                .is_some_and(|v| v.is_empty()),
            "CONFLICT",
        )?;
        let tx = self.db.transaction()?;
        for r in &pack.records {
            tx.execute(
                "INSERT OR IGNORE INTO records VALUES(?1,?2,?3,?4,?5)",
                params![
                    r.id,
                    r.version,
                    r.scope,
                    r.status,
                    serde_json::to_string(r)?
                ],
            )?;
        }
        tx.commit()?;
        // No grants/credentials are part of the import contract.
        Ok(json!({"status":"OK","preview":preview}))
    }
    pub fn encrypted_backup(&self) -> Result<(Vec<u8>, Zeroizing<String>)> {
        // SQLCipher must key the destination before the SQLite backup API runs.
        // Copying the live database file is intentionally not used.
        let parent = self
            .db
            .path()
            .and_then(|p| Path::new(p).parent())
            .ok_or(Error("IO_ERROR"))?;
        let snapshot = parent.join(format!(".snapshot-{}", id()));
        let result = (|| {
            let mut target = Store::open(&snapshot, &self.key, true)?;
            let backup = rusqlite::backup::Backup::new(&self.db, &mut target.db)?;
            backup.run_to_completion(64, std::time::Duration::from_millis(1), None)?;
            drop(backup);
            drop(target);
            require(
                std::fs::metadata(&snapshot)?.len() <= SNAPSHOT_LIMIT,
                "LIMIT_EXCEEDED",
            )?;
            let db_bytes = Zeroizing::new(std::fs::read(&snapshot)?);
            let key_hex = Zeroizing::new(hex::encode(self.key.as_slice()));
            let envelope = Zeroizing::new(serde_json::to_vec(&json!({
                "format":"alexandria-recovery","version":1,"key":key_hex.as_str(),"database":hex::encode(db_bytes.as_slice())
            }))?);
            let identity = age::x25519::Identity::generate();
            let recipient = identity.to_public();
            let encryptor =
                age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                    .map_err(|_| Error("BACKUP_ERROR"))?;
            let mut output = vec![];
            let mut writer = encryptor
                .wrap_output(&mut output)
                .map_err(|_| Error("BACKUP_ERROR"))?;
            writer.write_all(&envelope)?;
            writer.finish().map_err(|_| Error("BACKUP_ERROR"))?;
            use age::secrecy::ExposeSecret;
            let recovery = Zeroizing::new(identity.to_string().expose_secret().to_string());
            Ok((output, recovery))
        })();
        let _ = std::fs::remove_file(&snapshot);
        result
    }
}

pub fn markdown(pack: &Pack) -> String {
    let mut out=format!("# Alexandria context export\n\nExported: {}\n\nPlaintext. Keep this file private. JSON is the lossless companion.\n\n",pack.exported_at);
    for r in &pack.records {
        // Plain Markdown remains text; source references are never made into active HTML.
        out.push_str(&format!("## {} · v{} · {}\n\nScope: {} | Kind: {} | Sensitivity: {}\n\n{}\n\nSource: {} / {} / {}\n\n",r.id,r.version,r.status,r.scope,r.kind,r.sensitivity,r.text,r.source.provider,r.source.capture_method,r.source.reference));
    }
    out
}

pub fn recover_pack(encrypted: &[u8], identity: &str, staging_parent: &Path) -> Result<Pack> {
    require(encrypted.len() <= 150 * 1024 * 1024, "LIMIT_EXCEEDED")?;
    let identity: age::x25519::Identity = identity
        .trim()
        .parse()
        .map_err(|_| Error("INVALID_RECOVERY_KEY"))?;
    let decryptor = age::Decryptor::new(encrypted).map_err(|_| Error("INVALID_BACKUP"))?;
    let reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| Error("INVALID_RECOVERY_KEY"))?;
    let mut plain = Zeroizing::new(vec![]);
    reader
        .take(SNAPSHOT_LIMIT * 2 + 4097)
        .read_to_end(&mut plain)?;
    require(
        plain.len() as u64 <= SNAPSHOT_LIMIT * 2 + 4096,
        "LIMIT_EXCEEDED",
    )?;
    let value: Value = serde_json::from_slice(&plain)?;
    require(
        value["format"] == "alexandria-recovery" && value["version"] == 1,
        "INVALID_BACKUP",
    )?;
    // No archive paths or extraction at all: only a fixed schema and generated filename.
    let allowed = ["format", "version", "key", "database"];
    require(
        value
            .as_object()
            .is_some_and(|o| o.len() == 4 && o.keys().all(|k| allowed.contains(&k.as_str()))),
        "INVALID_BACKUP",
    )?;
    let key =
        Zeroizing::new(hex::decode(string(&value, "key")?).map_err(|_| Error("INVALID_BACKUP"))?);
    require(key.len() == 32, "INVALID_BACKUP")?;
    let raw = Zeroizing::new(
        hex::decode(string(&value, "database")?).map_err(|_| Error("INVALID_BACKUP"))?,
    );
    require(raw.len() as u64 <= SNAPSHOT_LIMIT, "LIMIT_EXCEEDED")?;
    let path = staging_parent.join(format!(".restore-{}", id()));
    let result = (|| {
        let mut file = crate::private_fs::create_private(&path)?;
        file.write_all(&raw)?;
        file.sync_all()?;
        drop(file);
        let mut k = Zeroizing::new([0; 32]);
        k.copy_from_slice(&key);
        let store = Store::open(&path, &k, false)?;
        let integrity: String = store
            .db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        require(integrity == "ok", "INVALID_BACKUP")?;
        let pack = store.export(None)?;
        parse_pack(&serde_json::to_vec(&pack)?)?;
        Ok(pack)
    })();
    let _ = std::fs::remove_file(&path);
    result
}
