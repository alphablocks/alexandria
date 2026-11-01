use alexandria_vault_core::{model::*, portability, rpc, Service, Store};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
fn draft(text: &str, scope: &str) -> Value {
    json!({"text":text,"scope":scope,"kind":"user_statement","sensitivity":"ordinary",
    "source":{"provider":"owner","capture_method":"explicit_save","reference":"synthetic:test","completeness":"selected_excerpt"}})
}
fn store(path: &Path) -> Store {
    Store::open(path, &random_key(), true).unwrap()
}
fn fixture() -> Pack {
    let mut pack = portability::parse_pack(include_bytes!(
        "../../../../research/horizontal-memory/example-context-pack.json"
    ))
    .unwrap();
    pack.records
        .sort_by(|a, b| (&a.id, a.version).cmp(&(&b.id, b.version)));
    pack
}

#[test]
fn v01_v10_real_cipher_wrong_key_and_no_plaintext() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("vault.db");
    let key = random_key();
    let mut s = Store::open(&path, &key, true).unwrap();
    s.save(&draft("SENTINEL_PRIVATE_VAULT_7349", "research"))
        .unwrap();
    drop(s);
    let bytes = std::fs::read(&path).unwrap();
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
    let sentinel = b"SENTINEL_PRIVATE_VAULT_7349";
    assert!(!bytes.windows(sentinel.len()).any(|w| w == sentinel));
    assert!(Store::open(&path, &random_key(), false).is_err());
    let s = Store::open(&path, &key, false).unwrap();
    assert_eq!(s.list().unwrap().len(), 1);
}
#[test]
fn v02_v03_v18_grants_filter_before_search_and_new_records_stay_private() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("v"));
    let a = s.save(&draft("TypeScript pnpm Cedar", "coding")).unwrap();
    let b = s.save(&draft("Python pytest Birch", "coding")).unwrap();
    let (cid, key) = s.pair("Claude label").unwrap();
    assert!(s.retrieve(&cid, "", None, 10).unwrap().is_empty());
    s.grant(&cid, &[a.id.clone()], None).unwrap();
    let result = s.retrieve(&cid, "pnpm", None, 10).unwrap();
    assert_eq!(result[0].id, a.id);
    assert!(s.retrieve(&cid, "pytest", None, 10).unwrap().is_empty());
    assert_eq!(
        s.retrieve(&cid, "", Some(&b.id), 1).unwrap_err().0,
        "NOT_FOUND"
    );
    assert_eq!(
        s.retrieve(&cid, "", Some("absent"), 1).unwrap_err().0,
        "NOT_FOUND"
    );
    let newer = s.save(&draft("Another Cedar record", "coding")).unwrap();
    assert!(s.retrieve(&cid, "", Some(&newer.id), 1).is_err());
    s.authenticate(&cid, &key).unwrap();
    assert_eq!(
        s.authenticate(&cid, "Claude label").unwrap_err().0,
        "DENIED"
    );
}
#[test]
fn v04_v05_v06_proposals_approval_idempotency_and_stale_update() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v");
    let key = random_key();
    let mut service = Service::new(&path);
    service.unlock(&key, true).unwrap();
    let (cid, token) = service.store().unwrap().pair("Assistant").unwrap();
    let mut input = draft("Use short paragraphs", "writing");
    input["operation_id"] = json!("op1");
    assert_eq!(
        service
            .tool(&cid, &token, "propose_context", &input)
            .unwrap_err()
            .0,
        "DENIED"
    );
    service
        .store()
        .unwrap()
        .grant(&cid, &[], Some("writing"))
        .unwrap();
    let pending = service
        .tool(&cid, &token, "propose_context", &input)
        .unwrap();
    assert_eq!(pending["status"], "PENDING_APPROVAL");
    assert!(service.store().unwrap().list().unwrap().is_empty());
    let pid = pending["proposal_id"].as_str().unwrap();
    assert_eq!(
        service
            .tool(&cid, &token, "resolve", &json!({"id":pid,"approve":true}))
            .unwrap_err()
            .0,
        "DENIED"
    );
    assert_eq!(
        service
            .tool(&cid, &token, "propose_context", &input)
            .unwrap()["proposal_id"],
        pid
    );
    let mut changed = input.clone();
    changed["text"] = json!("different");
    assert_eq!(
        service
            .tool(&cid, &token, "propose_context", &changed)
            .unwrap_err()
            .0,
        "CONFLICT"
    );
    let committed = service
        .owner("resolve", &json!({"id":pid,"approve":true}))
        .unwrap();
    assert_eq!(committed["record"]["version"], 1);
    let rid = committed["record"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        service
            .tool(&cid, &token, "proposal_status", &json!({"id":pid}))
            .unwrap()["status"],
        "APPROVED"
    );
    // Approval does not silently grant read access to a newly created record.
    assert!(service
        .tool(&cid, &token, "get_context", &json!({"id":rid}))
        .is_err());
    let mut edit = draft("Use Australian spelling", "writing");
    edit["id"] = json!(rid);
    edit["expected_version"] = json!(1);
    service.owner("save", &edit).unwrap();
    assert_eq!(service.owner("save", &edit).unwrap_err().0, "CONFLICT");
    assert_eq!(
        service.store().unwrap().history(&rid).unwrap()[0].status,
        "superseded"
    );
}
#[test]
fn v05_storage_write_failure_has_no_receipt_or_partial_record() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v");
    let mut s = store(&path);
    let mut input = draft("failure marker", "writing");
    let (cid, _) = s.pair("A").unwrap();
    s.grant(&cid, &[], Some("writing")).unwrap();
    input["operation_id"] = json!("fail1");
    let pid = s.propose(&cid, &input).unwrap()["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Make real SQLCipher reject writes, not a mocked return value.
    // A separate keyed connection takes the exclusive database lock.
    let key2 = random_key();
    drop(s);
    // Reopen with known key in a separate fixture; we do not expose production keys.
    let path2 = d.path().join("failure-vault");
    let mut s = Store::open(&path2, &key2, true).unwrap();
    let (cid, _) = s.pair("B").unwrap();
    s.grant(&cid, &[], Some("writing")).unwrap();
    let pid2 = s.propose(&cid, &input).unwrap()["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let blocker = rusqlite::Connection::open(&path2).unwrap();
    blocker
        .execute_batch(&format!(
            "PRAGMA key=\"x'{}'\"; BEGIN EXCLUSIVE;",
            hex::encode(key2.as_slice())
        ))
        .unwrap();
    assert_eq!(s.resolve(&pid2, true).unwrap_err().0, "STORAGE_ERROR");
    blocker.execute_batch("ROLLBACK;").unwrap();
    assert!(s.list().unwrap().is_empty());
    assert_eq!(
        s.proposal_status(&cid, &pid2).unwrap()["status"],
        "PENDING_APPROVAL"
    );
    assert_ne!(pid, pid2);
    s.resolve(&pid2, true).unwrap();
    assert_eq!(s.list().unwrap().len(), 1);
}
#[test]
fn v07_v08_revoked_locked_and_idle_calls_fail_closed() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v");
    let mut service = Service::new(&path);
    let key = random_key();
    service.unlock(&key, true).unwrap();
    let r = service
        .store()
        .unwrap()
        .save(&draft("metric units", "writing"))
        .unwrap();
    let (cid, token) = service.store().unwrap().pair("A").unwrap();
    service
        .store()
        .unwrap()
        .grant(&cid, &[r.id.clone()], Some("writing"))
        .unwrap();
    let mut p = draft("new preference", "writing");
    p["operation_id"] = json!("cancel");
    let pid = service.tool(&cid, &token, "propose_context", &p).unwrap()["proposal_id"]
        .as_str()
        .unwrap()
        .to_owned();
    service.owner("revoke", &json!({"id":cid})).unwrap();
    assert_eq!(
        service
            .tool(&cid, &token, "get_context", &json!({"id":r.id}))
            .unwrap_err()
            .0,
        "DENIED"
    );
    assert!(service
        .owner("resolve", &json!({"id":pid,"approve":true}))
        .is_err());
    service.lock();
    assert_eq!(service.owner("list", &json!({})).unwrap_err().0, "LOCKED");
    service.unlock(&key, false).unwrap();
    service.timeout = Duration::from_millis(1);
    std::thread::sleep(Duration::from_millis(3));
    assert_eq!(
        service
            .tool(&cid, &token, "search_context", &json!({"query":""}))
            .unwrap_err()
            .0,
        "LOCKED"
    );
}
#[test]
fn v12_v13_v14_age_backup_recovery_has_fresh_connections() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("v"));
    s.import(&fixture()).unwrap();
    let (cid, _) = s.pair("Old").unwrap();
    s.grant(&cid, &["sample-style".into()], Some("writing"))
        .unwrap();
    let before = s.export(None).unwrap();
    let (mut bytes, recovery) = s.encrypted_backup().unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1"));
    assert!(!bytes.windows(16).any(|w| w == b"Australian spell"));
    assert!(portability::recover_pack(&bytes, "bad-key", d.path()).is_err());
    let pack = portability::recover_pack(&bytes, &recovery, d.path()).unwrap();
    assert_eq!(pack.records, before.records);
    let mut restored = store(&d.path().join("fresh"));
    restored.import(&pack).unwrap();
    assert!(restored.connections().unwrap().is_empty());
    assert!(restored.proposals().unwrap().is_empty());
    bytes[100] ^= 1;
    assert!(portability::recover_pack(&bytes, &recovery, d.path()).is_err());
    assert!(!std::fs::read_dir(d.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".restore-")));
}
#[test]
fn v15_deletion_removes_versions_grants_and_linked_proposals() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("v"));
    let r = s.save(&draft("prefer train travel", "planning")).unwrap();
    let (cid, _) = s.pair("A").unwrap();
    s.grant(&cid, &[r.id.clone()], Some("planning")).unwrap();
    let mut p = draft("prefer bus", "planning");
    p["record_id"] = json!(r.id);
    p["expected_version"] = json!(1);
    p["operation_id"] = json!("edit");
    s.propose(&cid, &p).unwrap();
    s.delete(&r.id).unwrap();
    assert!(s.history(&r.id).unwrap().is_empty());
    assert!(s.proposals().unwrap().is_empty());
    assert!(s.retrieve(&cid, "train", None, 10).unwrap().is_empty());
}
#[test]
fn v16_roundtrip_dedupe_private_restore_and_conflict_atomicity() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("v"));
    let pack = fixture();
    assert_eq!(s.preview_import(&pack).unwrap()["added"], 3);
    s.import(&pack).unwrap();
    let exported = s.export(None).unwrap();
    assert_eq!(exported.records, pack.records);
    assert_eq!(s.preview_import(&pack).unwrap()["duplicates"], 3);
    s.import(&pack).unwrap();
    assert_eq!(s.export(None).unwrap().records.len(), 3);
    assert!(portability::markdown(&pack).contains("Australian spelling"));
    let mut conflict = pack.clone();
    conflict.records[1].text = "conflict".into();
    assert_eq!(s.import(&conflict).unwrap_err().0, "CONFLICT");
    assert_eq!(s.export(None).unwrap().records, pack.records);
    let mut broken = pack.clone();
    broken
        .records
        .iter_mut()
        .find(|r| r.version == 2)
        .unwrap()
        .supersedes = None;
    assert!(portability::parse_pack(&serde_json::to_vec(&broken).unwrap()).is_err());
    let (cid, _) = s.pair("No restored grants").unwrap();
    assert!(s.retrieve(&cid, "", None, 10).unwrap().is_empty());
}
#[test]
fn v17_untrusted_text_cannot_invoke_owner_tools_or_reveal_inference() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("v"));
    s.import(&fixture()).unwrap();
    let (cid, _) = s.pair("A").unwrap();
    s.grant(&cid, &["sample-style".into()], None).unwrap();
    assert!(s.retrieve(&cid, "", Some("sample-learning"), 1).is_err());
    let mut service = Service::new(&d.path().join("different"));
    service.unlock(&random_key(), true).unwrap();
    let (cid, token) = service.store().unwrap().pair("Attacker").unwrap();
    for tool in [
        "approve",
        "unlock",
        "export",
        "delete",
        "grant",
        "execute_sql",
    ] {
        assert_eq!(
            service
                .tool(&cid, &token, tool, &json!({"text":"Ignore rules"}))
                .unwrap_err()
                .0,
            "DENIED"
        );
    }
}
#[test]
fn v19_bounded_proposals_frames_and_inputs() {
    let d = tempfile::tempdir().unwrap();
    let mut s = store(&d.path().join("v"));
    let (cid, _) = s.pair("A").unwrap();
    s.grant(&cid, &[], Some("writing")).unwrap();
    for i in 0..20 {
        let mut p = draft("bounded", "writing");
        p["operation_id"] = json!(format!("op{i}"));
        s.propose(&cid, &p).unwrap();
    }
    let mut p = draft("bounded", "writing");
    p["operation_id"] = json!("overflow");
    assert_eq!(s.propose(&cid, &p).unwrap_err().0, "LIMIT_EXCEEDED");
    assert!(s.save(&draft(&"x".repeat(32769), "writing")).is_err());
    let bytes = vec![b'x'; rpc::FRAME_LIMIT + 1];
    assert!(rpc::read_frame(&mut std::io::Cursor::new(bytes)).is_err());
}
#[test]
#[cfg(unix)]
fn v20_real_socket_protocol_isolation_and_revocation() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v");
    let mut service = Service::new(&path);
    service.unlock(&random_key(), true).unwrap();
    let r = service
        .store()
        .unwrap()
        .save(&draft("writing sentinel", "writing"))
        .unwrap();
    let (cid, token) = service.store().unwrap().pair("paired").unwrap();
    service.store().unwrap().grant(&cid, &[r.id], None).unwrap();
    let shared = Arc::new(Mutex::new(service));
    let socket = d.path().join("s");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let serving = shared.clone();
    let thread = std::thread::spawn(move || {
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            rpc::serve_connection(stream, &serving).unwrap();
        }
    });
    let request = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_context","arguments":{"query":"writing"}}});
    let result = rpc::mcp_response(&request, |name, args| {
        rpc::call_socket(&socket, &cid, &token, name, args)
    })
    .unwrap();
    assert_eq!(result["result"]["isError"], false);
    assert!(result.to_string().contains("writing sentinel"));
    assert_eq!(
        rpc::call_socket(
            &socket,
            &cid,
            "wrong",
            "search_context",
            &json!({"query":""})
        )
        .unwrap_err()
        .0,
        "DENIED"
    );
    shared
        .lock()
        .unwrap()
        .owner("revoke", &json!({"id":cid}))
        .unwrap();
    assert_eq!(
        rpc::call_socket(
            &socket,
            &cid,
            &token,
            "search_context",
            &json!({"query":""})
        )
        .unwrap_err()
        .0,
        "DENIED"
    );
    thread.join().unwrap();
}
#[test]
#[cfg(unix)]
fn v07_dispatch_and_revoke_are_serialized() {
    let d = tempfile::tempdir().unwrap();
    let mut service = Service::new(&d.path().join("v"));
    service.unlock(&random_key(), true).unwrap();
    let (cid, token) = service.store().unwrap().pair("A").unwrap();
    let shared = Arc::new(Mutex::new(service));
    let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
    let holding = shared.lock().unwrap();
    let serving = shared.clone();
    let thread = std::thread::spawn(move || rpc::serve_connection(server, &serving));
    let mut request=json!({"connection_id":cid,"token":token.as_str(),"tool":"search_context","arguments":{"query":""}}).to_string();
    request.push('\n');
    client.write_all(request.as_bytes()).unwrap();
    // Revocation occurs before the worker can acquire dispatch's common mutex.
    let mut holding = holding;
    holding.owner("revoke", &json!({"id":cid})).unwrap();
    drop(holding);
    let mut reply = String::new();
    BufReader::new(&mut client).read_line(&mut reply).unwrap();
    assert!(reply.contains("DENIED"));
    client.write_all(&[rpc::RESPONSE_ACK]).unwrap();
    thread.join().unwrap().unwrap();
}
#[test]
fn protocol_initialization_and_tool_list_are_real_and_restricted() {
    let init = rpc::mcp_response(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        |_, _| panic!(),
    )
    .unwrap();
    assert_eq!(
        init["result"]["serverInfo"]["name"],
        "alexandria-local-vault"
    );
    let tools = rpc::tools();
    assert_eq!(tools.as_array().unwrap().len(), 4);
    assert!(!tools.to_string().contains("unlock"));
    assert!(rpc::mcp_response(
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        |_, _| panic!()
    )
    .is_none());
}

#[test]
fn protocol_stdio_frames_and_unknown_fields_cannot_bypass_grants() {
    let d = tempfile::tempdir().unwrap();
    let mut service = Service::new(&d.path().join("v"));
    service.unlock(&random_key(), true).unwrap();
    let r = service
        .store()
        .unwrap()
        .save(&draft("hidden", "writing"))
        .unwrap();
    let (cid, token) = service.store().unwrap().pair("A").unwrap();
    service
        .store()
        .unwrap()
        .grant(&cid, &[], Some("writing"))
        .unwrap();
    let mut attack = draft("overwrite hidden", "writing");
    attack["id"] = json!(r.id);
    attack["expected_version"] = json!(1);
    attack["operation_id"] = json!("attack");
    assert_eq!(
        service
            .tool(&cid, &token, "propose_context", &attack)
            .unwrap_err()
            .0,
        "INVALID_INPUT"
    );
    assert_eq!(
        service
            .tool(
                &cid,
                &token,
                "search_context",
                &json!({"query":"","limit":-1})
            )
            .unwrap_err()
            .0,
        "INVALID_INPUT"
    );
    let input=b"{bad json}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
    let mut output = vec![];
    rpc::run_stdio(std::io::Cursor::new(input), &mut output, |_, _| panic!()).unwrap();
    let output = String::from_utf8(output).unwrap();
    let lines: Vec<_> = output
        .lines()
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["error"]["code"], -32700);
    assert_eq!(lines[2]["result"]["tools"].as_array().unwrap().len(), 4);
}

#[test]
#[cfg(unix)]
fn v09_unavailable_service_is_not_an_empty_result() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(
        rpc::call_socket(
            &d.path().join("absent"),
            "synthetic",
            "synthetic",
            "search_context",
            &json!({"query":""})
        )
        .unwrap_err()
        .0,
        "UNAVAILABLE"
    );
}

#[test]
fn v11_expiry_scrubs_proposal_text_but_preserves_retry_identity() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v");
    let key = random_key();
    let mut s = Store::open(&path, &key, true).unwrap();
    let (cid, _) = s.pair("A").unwrap();
    s.grant(&cid, &[], Some("writing")).unwrap();
    let mut p = draft("expiry sentinel", "writing");
    p["operation_id"] = json!("once");
    let pid = s.propose(&cid, &p).unwrap()["proposal_id"]
        .as_str()
        .unwrap()
        .to_string();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(&format!(
        "PRAGMA key=\"x'{}'\";",
        hex::encode(key.as_slice())
    ))
    .unwrap();
    db.execute("UPDATE proposals SET expires=0 WHERE id=?1", [&pid])
        .unwrap();
    db.execute("INSERT INTO audit VALUES('old','owner_save',0)", [])
        .unwrap();
    s.clean().unwrap();
    let payload: String = db
        .query_row("SELECT payload FROM proposals WHERE id=?1", [&pid], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(payload, "{}");
    assert_eq!(s.proposal_status(&cid, &pid).unwrap()["status"], "EXPIRED");
    assert_eq!(s.propose(&cid, &p).unwrap()["status"], "EXPIRED");
    assert_eq!(
        db.query_row("SELECT count(*) FROM audit WHERE id='old'", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(s.proposals().unwrap().is_empty());
}

#[test]
fn native_gate_closes_before_the_monitor_can_acquire_the_service_mutex() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let d = tempfile::tempdir().unwrap();
    let gate = Arc::new(AtomicBool::new(true));
    let mut s = Service::with_gate(&d.path().join("gated"), gate.clone());
    let key = random_key();
    let unlocked = s.unlock(&key, true).unwrap();
    let (cid, token) = s.store().unwrap().pair("synthetic").unwrap();
    gate.store(false, Ordering::SeqCst);
    assert_eq!(
        s.tool(&cid, &token, "search_context", &json!({"query":""}))
            .unwrap_err()
            .0,
        "LOCKED"
    );
    let closed = s.status();
    assert_eq!(closed["unlocked"], false);
    assert!(closed["epoch"].as_u64().unwrap() > unlocked["epoch"].as_u64().unwrap());
    assert_eq!(
        s.unlock(&key, false).unwrap_err().0,
        "LOCK_MONITOR_UNAVAILABLE"
    );
    gate.store(true, Ordering::SeqCst);
    assert_eq!(
        s.tool(&cid, &token, "search_context", &json!({"query":""}))
            .unwrap_err()
            .0,
        "LOCKED"
    );
    assert_eq!(s.unlock(&key, false).unwrap()["unlocked"], true);
}

#[test]
#[cfg(unix)]
fn response_ack_keeps_production_server_open_but_does_not_block_revocation() {
    let d = tempfile::tempdir().unwrap();
    let mut service = Service::new(&d.path().join("v"));
    service.unlock(&random_key(), true).unwrap();
    let (cid, token) = service.store().unwrap().pair("ack-test").unwrap();
    let shared = Arc::new(Mutex::new(service));
    let serving = shared.clone();
    let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
    let (finished, completion) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = rpc::serve_connection(server, &serving);
        finished.send(result).unwrap();
    });
    let request = json!({"connection_id":cid,"token":token.as_str(),"tool":"search_context","arguments":{"query":""}});
    writeln!(client, "{}", request).unwrap();
    let frame = rpc::read_frame(&mut BufReader::new(&mut client))
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&frame.0).unwrap()["ok"],
        true
    );
    // Even though delivery is awaiting acknowledgement, owner revocation works.
    shared
        .lock()
        .unwrap()
        .store()
        .unwrap()
        .revoke(&cid)
        .unwrap();
    assert!(matches!(
        completion.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    client.write_all(&[rpc::RESPONSE_ACK]).unwrap();
    completion
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
}

#[test]
#[cfg(unix)]
fn absent_response_ack_times_out_instead_of_hanging_the_listener() {
    let d = tempfile::tempdir().unwrap();
    let mut service = Service::new(&d.path().join("v"));
    service.unlock(&random_key(), true).unwrap();
    let (cid, token) = service.store().unwrap().pair("no-ack").unwrap();
    let service = Arc::new(Mutex::new(service));
    let (mut client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    server
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let worker = std::thread::spawn(move || rpc::serve_stream(&mut server, &service));
    writeln!(client,"{}",json!({"connection_id":cid,"token":token.as_str(),"tool":"search_context","arguments":{"query":""}})).unwrap();
    rpc::read_frame(&mut BufReader::new(&mut client))
        .unwrap()
        .unwrap();
    assert_eq!(worker.join().unwrap().unwrap_err().0, "IO_ERROR");
}

#[test]
#[cfg(windows)]
fn windows_pipe_enforces_core_grants_lock_and_revocation() {
    use alexandria_vault_core::windows::pipe;
    let d = tempfile::tempdir().unwrap();
    let mut service = Service::new(&d.path().join("v"));
    service.unlock(&random_key(), true).unwrap();
    let record = service
        .store()
        .unwrap()
        .save(&draft("windows synthetic shared", "test"))
        .unwrap();
    let (cid, token) = service.store().unwrap().pair("windows-test").unwrap();
    service
        .store()
        .unwrap()
        .grant(&cid, &[record.id], None)
        .unwrap();
    let shared = Arc::new(Mutex::new(service));
    let serving = shared.clone();
    let mut listener = pipe::Listener::bind().unwrap();
    let worker = std::thread::spawn(move || {
        for _ in 0..3 {
            let mut p = listener.accept().unwrap();
            rpc::serve_stream(&mut p, &serving).unwrap();
        }
    });
    assert_eq!(
        rpc::call_pipe(
            &cid,
            &token,
            "search_context",
            &json!({"query":"synthetic"})
        )
        .unwrap()["records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    shared
        .lock()
        .unwrap()
        .store()
        .unwrap()
        .revoke(&cid)
        .unwrap();
    assert_eq!(
        rpc::call_pipe(&cid, &token, "search_context", &json!({"query":""}))
            .unwrap_err()
            .0,
        "DENIED"
    );
    shared.lock().unwrap().lock();
    assert_eq!(
        rpc::call_pipe(&cid, &token, "search_context", &json!({"query":""}))
            .unwrap_err()
            .0,
        "LOCKED"
    );
    worker.join().unwrap();
}
