use crate::{model::*, Store};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct Service {
    pub(crate) store: Option<Store>,
    path: PathBuf,
    last_owner: Instant,
    pub timeout: Duration,
    gate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    epoch: u64,
}
impl Service {
    pub fn new(path: &Path) -> Self {
        Self {
            store: None,
            path: path.into(),
            last_owner: Instant::now(),
            timeout: Duration::from_secs(900),
            gate: None,
            epoch: 0,
        }
    }
    pub fn with_gate(path: &Path, gate: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        let mut s = Self::new(path);
        s.gate = Some(gate);
        s
    }
    fn available(&self) -> bool {
        self.gate
            .as_ref()
            .map_or(true, |g| g.load(std::sync::atomic::Ordering::SeqCst))
    }
    pub fn status(&mut self) -> Value {
        self.expire();
        json!({"initialized":self.path.exists(),"unlocked":self.store.is_some(),"native":true,"epoch":self.epoch,
            "recovery_warning":"Keep recovery keys separately. Alexandria cannot reset a lost key."})
    }
    pub fn expire(&mut self) {
        if !self.available() || self.last_owner.elapsed() >= self.timeout {
            self.lock();
        }
    }
    pub fn touch(&mut self) {
        self.last_owner = Instant::now();
    }
    pub fn lock(&mut self) {
        if self.store.is_some() {
            self.epoch = self.epoch.saturating_add(1);
        }
        self.store = None;
    }
    pub fn unlock(&mut self, key: &[u8; 32], create: bool) -> Result<Value> {
        self.expire();
        require(self.available(), "LOCK_MONITOR_UNAVAILABLE")?;
        let store = Store::open(&self.path, key, create)?;
        require(self.available(), "LOCK_MONITOR_UNAVAILABLE")?;
        self.store = Some(store);
        self.epoch = self.epoch.saturating_add(1);
        self.touch();
        Ok(self.status())
    }
    pub fn store(&mut self) -> Result<&mut Store> {
        self.expire();
        self.store.as_mut().ok_or(Error("LOCKED"))
    }
    pub fn owner(&mut self, action: &str, p: &Value) -> Result<Value> {
        if action == "status" {
            return Ok(self.status());
        }
        if action == "lock" {
            self.lock();
            return Ok(self.status());
        }
        if action == "touch" {
            self.expire();
            if self.store.is_some() {
                self.touch();
            }
            return Ok(json!({"status":"OK"}));
        }
        // UI polling never renews the owner-interaction timer.
        let store = self.store()?;
        store.clean()?;
        match action {
            "list" => Ok(serde_json::to_value(store.list()?)?),
            "history" => Ok(serde_json::to_value(store.history(string(p, "id")?)?)?),
            "save" => Ok(serde_json::to_value(store.save(p)?)?),
            "delete" => store.delete(string(p, "id")?),
            "connections" => Ok(json!(store.connections()?)),
            "grant" => {
                let ids: Vec<String> = serde_json::from_value(
                    p.get("record_ids").cloned().ok_or(Error("INVALID_INPUT"))?,
                )?;
                store.grant(
                    string(p, "id")?,
                    &ids,
                    p.get("write_scope").and_then(Value::as_str),
                )
            }
            "revoke" => store.revoke(string(p, "id")?),
            "proposals" => store.proposals().map(|v| json!(v)),
            "resolve" => store.resolve(
                string(p, "id")?,
                p.get("approve")
                    .and_then(Value::as_bool)
                    .ok_or(Error("INVALID_INPUT"))?,
            ),
            _ => Err(Error("DENIED")),
        }
    }
    pub fn tool(&mut self, cid: &str, token: &str, name: &str, args: &Value) -> Result<Value> {
        let store = self.store()?;
        store.authenticate(cid, token)?;
        match name {
            "search_context" => {
                fields(args, &["query", "limit"])?;
                let limit = match args.get("limit") {
                    Some(v) => v
                        .as_u64()
                        .filter(|n| *n > 0 && *n <= 20)
                        .ok_or(Error("INVALID_INPUT"))? as usize,
                    None => 10,
                };
                let records = store.retrieve(cid, string(args, "query")?, None, limit)?;
                // Explicit continuation signal: callers refine the query rather than
                // mistaking a response bound for the complete accessible corpus.
                Ok(
                    json!({"status":"OK","records":records,"bounded":true,"max_records":limit,"note":"Results bounded; refine your query. No full-history access."}),
                )
            }
            "get_context" => {
                fields(args, &["id"])?;
                validate_text(string(args, "id")?, 128)?;
                Ok(
                    json!({"status":"OK","records":store.retrieve(cid,"",Some(string(args,"id")?),1)?}),
                )
            }
            "propose_context" => store.propose(cid, args),
            "proposal_status" => {
                fields(args, &["id"])?;
                store.proposal_status(cid, string(args, "id")?)
            }
            _ => Err(Error("DENIED")),
        }
    }
}
