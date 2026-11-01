use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self("STORAGE_ERROR")
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self("INVALID_INPUT")
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("IO_ERROR")
    }
}
pub type Result<T> = std::result::Result<T, Error>;
#[cfg(windows)]
impl From<alexandria_windows::Error> for Error {
    fn from(e: alexandria_windows::Error) -> Self {
        Self(e.0)
    }
}
pub fn require(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(code))
    }
}
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub fn hash(s: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s))
}
pub fn random_key() -> zeroize::Zeroizing<[u8; 32]> {
    use rand::RngCore;
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    key
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub provider: String,
    pub capture_method: String,
    pub reference: String,
    pub completeness: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Previous {
    pub id: String,
    pub version: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub version: i64,
    pub scope: String,
    pub kind: String,
    pub text: String,
    pub status: String,
    pub source: Source,
    pub created_at: String,
    pub updated_at: String,
    pub approved_at: Option<String>,
    pub supersedes: Option<Previous>,
    pub sensitivity: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub format: String,
    pub schema_version: u32,
    pub synthetic: bool,
    pub exported_at: String,
    pub export_scope: Vec<String>,
    pub exclusions: Vec<String>,
    pub records: Vec<Record>,
}
pub fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or(Error("INVALID_INPUT"))
}
pub fn validate_text(v: &str, limit: usize) -> Result<()> {
    require(
        !v.trim().is_empty() && v.len() <= limit && !v.contains('\0'),
        "INVALID_INPUT",
    )
}
pub fn fields(v: &Value, allowed: &[&str]) -> Result<()> {
    require(
        v.as_object()
            .is_some_and(|o| o.keys().all(|k| allowed.contains(&k.as_str()))),
        "INVALID_INPUT",
    )
}
pub fn validate_record(r: &Record) -> Result<()> {
    validate_text(&r.id, 128)?;
    validate_text(&r.scope, 100)?;
    validate_text(&r.text, 32 * 1024)?;
    require(
        r.version > 0 && ["active", "superseded", "proposed"].contains(&r.status.as_str()),
        "INVALID_INPUT",
    )?;
    require(
        ["user_statement", "assistant_inference", "source_excerpt"].contains(&r.kind.as_str()),
        "INVALID_INPUT",
    )?;
    require(
        ["ordinary", "sensitive"].contains(&r.sensitivity.as_str()),
        "INVALID_INPUT",
    )?;
    for v in [&r.created_at, &r.updated_at] {
        chrono::DateTime::parse_from_rfc3339(v).map_err(|_| Error("INVALID_INPUT"))?;
    }
    require(
        chrono::DateTime::parse_from_rfc3339(&r.updated_at).unwrap()
            >= chrono::DateTime::parse_from_rfc3339(&r.created_at).unwrap(),
        "INVALID_INPUT",
    )?;
    if let Some(t) = &r.approved_at {
        chrono::DateTime::parse_from_rfc3339(t).map_err(|_| Error("INVALID_INPUT"))?;
    }
    require(
        r.status != "active" || r.approved_at.is_some(),
        "INVALID_INPUT",
    )?;
    require(
        r.status != "proposed" || r.approved_at.is_none(),
        "INVALID_INPUT",
    )?;
    for v in [
        &r.source.provider,
        &r.source.capture_method,
        &r.source.reference,
        &r.source.completeness,
    ] {
        validate_text(v, 2048)?;
    }
    Ok(())
}
