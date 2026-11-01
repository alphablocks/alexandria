use crate::model::*;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

pub struct Store {
    pub(crate) db: Connection,
    pub(crate) key: Zeroizing<[u8; 32]>,
}
impl Store {
    pub fn open(path: &Path, key: &[u8; 32], create: bool) -> Result<Self> {
        require(create || path.is_file(), "NOT_FOUND")?;
        require(!create || !path.exists(), "ALREADY_EXISTS")?;
        if create {
            drop(crate::private_fs::create_private(path)?);
        }
        #[cfg(windows)]
        alexandria_windows::fs::reject_reparse(path)?;
        let db = Connection::open(path)?;
        // A raw random key avoids password KDF weaknesses and never reaches logs.
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex::encode(key)));
        db.execute_batch(&pragma)?;
        let cipher: String = db
            .query_row("PRAGMA cipher_version", [], |r| r.get(0))
            .map_err(|_| Error("ENCRYPTION_UNAVAILABLE"))?;
        require(!cipher.is_empty(), "ENCRYPTION_UNAVAILABLE")?;
        db.execute_batch(
            "PRAGMA cipher_memory_security=ON; PRAGMA temp_store=MEMORY;
            PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;",
        )?;
        // Wrong keys and corrupted files fail before any schema operation.
        db.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })?;
        if create {
            db.execute_batch("BEGIN;
                CREATE TABLE records(id TEXT NOT NULL, version INTEGER NOT NULL, scope TEXT NOT NULL,
                    status TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(id,version));
                CREATE INDEX scope_status ON records(scope,status);
                CREATE TABLE connections(id TEXT PRIMARY KEY,label TEXT NOT NULL,verifier TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,write_scope TEXT);
                CREATE TABLE grants(connection_id TEXT NOT NULL,record_id TEXT NOT NULL,
                    PRIMARY KEY(connection_id,record_id));
                CREATE TABLE proposals(id TEXT PRIMARY KEY,connection_id TEXT NOT NULL,operation TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL,
                    receipt TEXT,created_at TEXT NOT NULL,expires INTEGER NOT NULL,
                    UNIQUE(connection_id,operation));
                CREATE TABLE audit(id TEXT PRIMARY KEY,event TEXT NOT NULL,at INTEGER NOT NULL);
                PRAGMA user_version=1; COMMIT;")?;
        }
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        require(version == 1, "UNSUPPORTED_VERSION")?;
        Ok(Self {
            db,
            key: Zeroizing::new(*key),
        })
    }
    pub fn clean(&self) -> Result<()> {
        let t = chrono::Utc::now().timestamp();
        self.db.execute("UPDATE proposals SET state='EXPIRED',payload='{}',receipt=NULL WHERE state='pending' AND expires<=?1", [t])?;
        self.db
            .execute("DELETE FROM audit WHERE at<?1", [t - 7 * 86400])?;
        Ok(())
    }
    fn audit(&self, event: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO audit VALUES(?1,?2,?3)",
            params![id(), event, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<Record>> {
        read_records(
            &self.db,
            "SELECT data FROM records WHERE status!='superseded' ORDER BY id,version",
            [],
        )
    }
    pub fn history(&self, id: &str) -> Result<Vec<Record>> {
        read_records(
            &self.db,
            "SELECT data FROM records WHERE id=?1 ORDER BY version",
            [id],
        )
    }
    pub fn save(&mut self, input: &Value) -> Result<Record> {
        let record = prepare_record(&self.db, input)?;
        let tx = self.db.transaction()?;
        insert_record(&tx, &record)?;
        tx.commit()?;
        // Do not let an optional audit failure turn a committed write into a retry.
        let _ = self.audit("owner_save");
        Ok(record)
    }
    pub fn delete(&mut self, record_id: &str) -> Result<Value> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM grants WHERE record_id=?1", [record_id])?;
        tx.execute(
            "UPDATE proposals SET state='DELETED',payload='{}',receipt=NULL WHERE json_extract(payload,'$.record_id')=?1
            OR json_extract(receipt,'$.id')=?1",
            [record_id],
        )?;
        let count = tx.execute("DELETE FROM records WHERE id=?1", [record_id])?;
        require(count > 0, "NOT_FOUND")?;
        tx.commit()?;
        // secure_delete covers logical pages; VACUUM rewrites retained pages.
        // Filesystem/SSD snapshots remain outside this logical deletion claim.
        self.db.execute_batch("VACUUM;")?;
        let _ = self.audit("owner_delete");
        Ok(json!({"status":"OK"}))
    }
    pub fn pair(&mut self, label: &str) -> Result<(String, Zeroizing<String>)> {
        validate_text(label, 100)?;
        let n: i64 = self
            .db
            .query_row("SELECT count(*) FROM connections", [], |r| r.get(0))?;
        require(n < 100, "LIMIT_EXCEEDED")?;
        let cid = id();
        let secret = Zeroizing::new(hex::encode(random_key().as_slice()));
        self.db.execute(
            "INSERT INTO connections(id,label,verifier) VALUES(?1,?2,?3)",
            params![cid, label, hash(secret.as_bytes())],
        )?;
        Ok((cid, secret))
    }
    pub fn authenticate(&self, cid: &str, token: &str) -> Result<()> {
        use subtle::ConstantTimeEq;
        let row: Option<(String, bool)> = self
            .db
            .query_row(
                "SELECT verifier,revoked FROM connections WHERE id=?1",
                [cid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (expected, revoked) = row.ok_or(Error("DENIED"))?;
        let got = hash(token.as_bytes());
        require(
            !revoked && bool::from(expected.as_bytes().ct_eq(got.as_bytes())),
            "DENIED",
        )
    }
    pub fn connections(&self) -> Result<Vec<Value>> {
        let mut q = self
            .db
            .prepare("SELECT id,label,revoked,write_scope FROM connections ORDER BY rowid")?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut out = vec![];
        for row in rows {
            let (cid, label, revoked, write_scope) = row?;
            let mut g = self.db.prepare(
                "SELECT record_id FROM grants WHERE connection_id=?1 ORDER BY record_id",
            )?;
            let ids = g
                .query_map([&cid], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            out.push(json!({"id":cid,"label":label,"revoked":revoked,"write_scope":write_scope,"record_ids":ids}));
        }
        Ok(out)
    }
    pub fn grant(&mut self, cid: &str, ids: &[String], write_scope: Option<&str>) -> Result<Value> {
        require(ids.len() <= 10_000, "LIMIT_EXCEEDED")?;
        if let Some(scope) = write_scope {
            validate_text(scope, 100)?;
        }
        let tx = self.db.transaction()?;
        let revoked: bool = tx
            .query_row("SELECT revoked FROM connections WHERE id=?1", [cid], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or(Error("NOT_FOUND"))?;
        require(!revoked, "DENIED")?;
        for rid in ids {
            require(
                tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1 AND status='active')",
                    [rid],
                    |r| r.get(0),
                )?,
                "NOT_FOUND",
            )?;
        }
        tx.execute("DELETE FROM grants WHERE connection_id=?1", [cid])?;
        for rid in ids {
            tx.execute(
                "INSERT OR IGNORE INTO grants VALUES(?1,?2)",
                params![cid, rid],
            )?;
        }
        tx.execute(
            "UPDATE connections SET write_scope=?2 WHERE id=?1",
            params![cid, write_scope],
        )?;
        tx.execute(
            "UPDATE proposals SET state='CANCELLED',payload='{}',receipt=NULL WHERE connection_id=?1 AND state='pending'",
            [cid],
        )?;
        tx.commit()?;
        Ok(json!({"status":"OK"}))
    }
    pub fn revoke(&mut self, cid: &str) -> Result<Value> {
        let tx = self.db.transaction()?;
        require(
            tx.execute(
                "UPDATE connections SET revoked=1,write_scope=NULL WHERE id=?1",
                [cid],
            )? > 0,
            "NOT_FOUND",
        )?;
        tx.execute("DELETE FROM grants WHERE connection_id=?1", [cid])?;
        tx.execute("DELETE FROM proposals WHERE connection_id=?1", [cid])?;
        tx.commit()?;
        Ok(json!({"status":"OK"}))
    }
    pub fn retrieve(
        &self,
        cid: &str,
        query: &str,
        record_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Record>> {
        require(
            query.len() <= 1000 && limit > 0 && limit <= 20,
            "INVALID_INPUT",
        )?;
        // Filter by grants and approved lifecycle in SQL before matching. No
        // global term frequency/count data from inaccessible records is used.
        let mut records = read_records(
            &self.db,
            "SELECT r.data FROM records r JOIN grants g ON g.record_id=r.id
            WHERE g.connection_id=?1 AND r.status='active' ORDER BY r.id",
            [cid],
        )?;
        let words: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
        records.retain(|r| {
            record_id.map_or(true, |id| r.id == id)
                && words.iter().all(|w| r.text.to_lowercase().contains(w))
        });
        if record_id.is_some() && records.is_empty() {
            return Err(Error("NOT_FOUND"));
        }
        records.truncate(limit);
        let mut bounded = Vec::new();
        for r in records {
            bounded.push(r);
            if serde_json::to_vec(&bounded)?.len() > 60 * 1024 {
                bounded.pop();
                break;
            }
        }
        Ok(bounded)
    }
    pub fn proposals(&self) -> Result<Vec<Value>> {
        self.clean()?;
        let mut q=self.db.prepare("SELECT p.id,p.connection_id,c.label,p.payload,p.state,p.created_at
            FROM proposals p JOIN connections c ON c.id=p.connection_id WHERE p.state='pending' ORDER BY p.created_at")?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = vec![];
        for row in rows {
            let (id, cid, label, payload, state, at) = row?;
            out.push(json!({"id":id,"connection_id":cid,"connection_label":label,
                "payload":serde_json::from_str::<Value>(&payload)?,"state":state,"created_at":at}));
        }
        Ok(out)
    }
    pub fn propose(&mut self, cid: &str, input: &Value) -> Result<Value> {
        fields(
            input,
            &[
                "scope",
                "text",
                "kind",
                "source",
                "record_id",
                "expected_version",
                "sensitivity",
                "operation_id",
            ],
        )?;
        require(
            input.get("record_id").is_none_or(Value::is_string)
                && input.get("expected_version").is_none_or(Value::is_i64),
            "INVALID_INPUT",
        )?;
        require(
            input.get("kind").is_none_or(Value::is_string)
                && input.get("sensitivity").is_none_or(Value::is_string),
            "INVALID_INPUT",
        )?;
        require(
            input.get("record_id").is_some() == input.get("expected_version").is_some(),
            "INVALID_INPUT",
        )?;
        self.clean()?;
        let scope = string(input, "scope")?;
        let allowed: Option<String> = self
            .db
            .query_row(
                "SELECT write_scope FROM connections WHERE id=?1 AND revoked=0",
                [cid],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        require(allowed.as_deref() == Some(scope), "DENIED")?;
        validate_text(string(input, "text")?, 32 * 1024)?;
        let op = string(input, "operation_id")?;
        validate_text(op, 128)?;
        let encoded = serde_json::to_string(input)?;
        let fingerprint = hash(encoded.as_bytes());
        let prior: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT id,fingerprint FROM proposals WHERE connection_id=?1 AND operation=?2",
                params![cid, op],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((pid, fp)) = prior {
            require(fp == fingerprint, "CONFLICT")?;
            return self.proposal_status(cid, &pid);
        }
        let count: i64 = self.db.query_row(
            "SELECT count(*) FROM proposals WHERE connection_id=?1 AND state='pending'",
            [cid],
            |r| r.get(0),
        )?;
        require(count < 20, "LIMIT_EXCEEDED")?;
        let all: i64 = self.db.query_row(
            "SELECT count(*) FROM proposals WHERE connection_id=?1",
            [cid],
            |r| r.get(0),
        )?;
        require(all < 10_000, "LIMIT_EXCEEDED")?;
        if let Some(rid) = input.get("record_id").and_then(Value::as_str) {
            self.retrieve(cid, "", Some(rid), 1)?;
        }
        let mut draft = input.clone();
        if let Some(rid) = draft.get("record_id").cloned() {
            draft["id"] = rid;
        }
        prepare_record(&self.db, &draft)?;
        let pid = id();
        self.db.execute(
            "INSERT INTO proposals VALUES(?1,?2,?3,?4,?5,'pending',NULL,?6,?7)",
            params![
                pid,
                cid,
                op,
                fingerprint,
                encoded,
                now(),
                chrono::Utc::now().timestamp() + 86400
            ],
        )?;
        Ok(json!({"status":"PENDING_APPROVAL","proposal_id":pid}))
    }
    pub fn proposal_status(&self, cid: &str, pid: &str) -> Result<Value> {
        self.clean()?;
        let permitted:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM connections WHERE id=?1 AND revoked=0 AND write_scope IS NOT NULL)",
            [cid],|r|r.get(0))?;
        require(permitted, "DENIED")?;
        let result: Option<(String, Option<String>)> = self
            .db
            .query_row(
                "SELECT state,receipt FROM proposals WHERE id=?1 AND connection_id=?2",
                params![pid, cid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (state, receipt) = result.ok_or(Error("NOT_FOUND"))?;
        Ok(
            json!({"status":if state=="pending" {"PENDING_APPROVAL"}else{&state},
            "proposal_id":pid,"receipt":receipt.map(|r|serde_json::from_str::<Value>(&r)).transpose()?}),
        )
    }
    pub fn resolve(&mut self, pid: &str, approve: bool) -> Result<Value> {
        self.clean()?;
        let (cid, encoded, state): (String, String, String) = self
            .db
            .query_row(
                "SELECT connection_id,payload,state FROM proposals WHERE id=?1",
                [pid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(Error("NOT_FOUND"))?;
        require(state == "pending", "CONFLICT")?;
        if !approve {
            self.db.execute(
                "UPDATE proposals SET state='REJECTED',payload='{}' WHERE id=?1",
                [pid],
            )?;
            return Ok(json!({"status":"REJECTED"}));
        }
        let mut draft: Value = serde_json::from_str(&encoded)?;
        let allowed: Option<String> = self
            .db
            .query_row(
                "SELECT write_scope FROM connections WHERE id=?1 AND revoked=0",
                [&cid],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        require(
            allowed.as_deref() == draft.get("scope").and_then(Value::as_str),
            "DENIED",
        )?;
        if let Some(rid) = draft.get("record_id").and_then(Value::as_str) {
            self.retrieve(&cid, "", Some(rid), 1)?;
        }
        if let Some(rid) = draft.get("record_id").cloned() {
            draft["id"] = rid;
        }
        let record = prepare_record(&self.db, &draft)?;
        let receipt = serde_json::to_string(&json!({"id":record.id,"version":record.version}))?;
        let tx = self.db.transaction()?;
        insert_record(&tx, &record)?;
        tx.execute(
            "UPDATE proposals SET state='APPROVED',receipt=?2,payload='{}' WHERE id=?1",
            params![pid, receipt],
        )?;
        tx.commit()?;
        Ok(json!({"status":"APPROVED","record":record}))
    }
}

pub(crate) fn read_records<P: rusqlite::Params>(
    db: &Connection,
    sql: &str,
    p: P,
) -> Result<Vec<Record>> {
    let mut q = db.prepare(sql)?;
    let rows = q.query_map(p, |r| r.get::<_, String>(0))?;
    rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
}
fn prepare_record(db: &Connection, input: &Value) -> Result<Record> {
    let rid = input
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(id);
    let old: Option<String> = db
        .query_row(
            "SELECT data FROM records WHERE id=?1 ORDER BY version DESC LIMIT 1",
            [&rid],
            |r| r.get(0),
        )
        .optional()?;
    let old: Option<Record> = old.map(|r| serde_json::from_str(&r)).transpose()?;
    if let Some(r) = &old {
        require(
            input.get("expected_version").and_then(Value::as_i64) == Some(r.version),
            "CONFLICT",
        )?;
        require(
            string(input, "scope")? == r.scope,
            "SCOPE_CHANGE_REQUIRES_NEW_RECORD",
        )?;
    } else {
        require(
            input.get("expected_version").is_none_or(Value::is_null),
            "CONFLICT",
        )?;
        let n: i64 = db.query_row("SELECT count(DISTINCT id) FROM records", [], |r| r.get(0))?;
        require(n < 10_000, "LIMIT_EXCEEDED")?;
    }
    let time = now();
    let r = Record {
        id: rid,
        version: old.as_ref().map_or(1, |r| r.version + 1),
        scope: string(input, "scope")?.into(),
        kind: input
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("user_statement")
            .into(),
        text: string(input, "text")?.into(),
        status: "active".into(),
        source: serde_json::from_value(
            input.get("source").cloned().ok_or(Error("INVALID_INPUT"))?,
        )?,
        created_at: old
            .as_ref()
            .map_or_else(|| time.clone(), |r| r.created_at.clone()),
        updated_at: time.clone(),
        approved_at: Some(time),
        supersedes: old.as_ref().map(|r| Previous {
            id: r.id.clone(),
            version: r.version,
        }),
        sensitivity: input
            .get("sensitivity")
            .and_then(Value::as_str)
            .unwrap_or("ordinary")
            .into(),
    };
    validate_record(&r)?;
    let (versions, bytes): (i64, i64) = db.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(data AS BLOB))),0) FROM records",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    require(
        versions < 50_000 && bytes + serde_json::to_vec(&r)?.len() as i64 <= 48 * 1024 * 1024,
        "LIMIT_EXCEEDED",
    )?;
    Ok(r)
}
pub(crate) fn insert_record(db: &Connection, r: &Record) -> Result<()> {
    if let Some(prev) = &r.supersedes {
        let text: String = db.query_row(
            "SELECT data FROM records WHERE id=?1 AND version=?2",
            params![prev.id, prev.version],
            |row| row.get(0),
        )?;
        let mut prior: Record = serde_json::from_str(&text)?;
        prior.status = "superseded".into();
        db.execute(
            "UPDATE records SET status='superseded',data=?3 WHERE id=?1 AND version=?2",
            params![prev.id, prev.version, serde_json::to_string(&prior)?],
        )?;
    }
    db.execute(
        "INSERT INTO records VALUES(?1,?2,?3,?4,?5)",
        params![
            r.id,
            r.version,
            r.scope,
            r.status,
            serde_json::to_string(r)?
        ],
    )?;
    Ok(())
}
