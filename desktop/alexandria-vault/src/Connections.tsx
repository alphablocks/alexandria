import { useState } from "react";
import { command, type Connection, type RecordItem } from "./api";
import { Confirm, Empty, Notice, Skeleton, errorText } from "./ui";

export default function Connections({ connections, records, reload }: { connections: Connection[] | null; records: RecordItem[] | null; reload: () => Promise<void> }) {
  const [label, setLabel] = useState("");
  const [paired, setPaired] = useState<{ id: string; label: string } | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [writeOn, setWriteOn] = useState(false);
  const [scope, setScope] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [rev, setRev] = useState<Connection | null>(null);

  async function pair() {
    setBusy(true); setErr("");
    try { setPaired(await command<{ id: string; label: string }>("pair", { label: label.trim() })); setLabel(""); await reload(); }
    catch (e) { setErr(errorText(e)); } finally { setBusy(false); }
  }
  function startGrant(c: Connection) {
    setEditing(c.id); setPicked(new Set(c.record_ids)); setWriteOn(!!c.write_scope); setScope(c.write_scope ?? "");
  }
  async function grant() {
    if (!editing) return;
    setBusy(true); setErr("");
    try {
      await command("grant", { id: editing, record_ids: [...picked], write_scope: writeOn && scope.trim() ? scope.trim() : null });
      setEditing(null); await reload();
    } catch (e) { setErr(errorText(e)); } finally { setBusy(false); }
  }
  async function revoke() {
    if (!rev) return;
    setBusy(true);
    try { await command("revoke", { id: rev.id }); if (editing === rev.id) setEditing(null); await reload(); }
    catch (e) { setErr(errorText(e)); } finally { setBusy(false); setRev(null); }
  }
  const toggle = (id: string) => setPicked((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  return (
    <section className="pane solo">
      <div className="pane-head"><h2>Connections</h2><span className="meta">New connections can read nothing until you choose records.</span></div>
      {err && <Notice tone="error" onDismiss={() => setErr("")}>{err}</Notice>}
      <div className="pairbox">
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label, e.g. Claude on this PC" maxLength={60} />
        <button className="btn primary" disabled={busy || !label.trim()} onClick={pair}>Pair</button>
      </div>
      {paired && (
        <Notice tone="info" onDismiss={() => setPaired(null)}>
          Paired <b>{paired.label}</b>. Use this connection ID in the adapter setup: <span className="mono sel">{paired.id}</span>. The credential is stored by the system, not shown here.
        </Notice>
      )}
      {!connections ? <Skeleton rows={3} /> : connections.length === 0 ? <Empty title="No connections">Pair an assistant adapter to share chosen records with it.</Empty> : (
        <div className="cards">
          {connections.map((c) => (
            <article key={c.id} className={`card ${c.revoked ? "dim" : ""}`}>
              <div className="pane-head">
                <div><h3>{c.label}</h3><span className="meta mono sel">{c.id}</span></div>
                <div className="row">
                  {c.revoked ? <span className="tag">Revoked</span> : <>
                    <button className="btn ghost sm" onClick={() => editing === c.id ? setEditing(null) : startGrant(c)}>{editing === c.id ? "Close" : "Choose access"}</button>
                    <button className="btn ghost sm danger-text" onClick={() => setRev(c)}>Revoke</button>
                  </>}
                </div>
              </div>
              <p className="meta">Reads {c.record_ids.length} record{c.record_ids.length === 1 ? "" : "s"} · {c.write_scope ? `may propose into "${c.write_scope}"` : "read-only"}</p>
              {editing === c.id && (
                <div className="grant">
                  {!records?.length ? <p className="fine">No records to share yet.</p> : (
                    <ul className="checks">
                      {records.filter((r) => r.status === "active").map((r) => (
                        <li key={r.id}><label>
                          <input type="checkbox" checked={picked.has(r.id)} onChange={() => toggle(r.id)} />
                          <span className="clip">{r.text}</span>
                          <span className="meta">{r.scope}{r.sensitivity === "sensitive" ? " · sensitive" : ""}</span>
                        </label></li>
                      ))}
                    </ul>
                  )}
                  <label className="inline"><input type="checkbox" checked={writeOn} onChange={(e) => setWriteOn(e.target.checked)} /> Allow proposals (you still approve each one)</label>
                  {writeOn && <input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="Destination scope for proposals" />}
                  <div className="row end">
                    <span className="meta grow">{picked.size} selected</span>
                    <button className="btn primary" disabled={busy || (writeOn && !scope.trim())} onClick={grant}>Save access</button>
                  </div>
                </div>
              )}
            </article>
          ))}
        </div>
      )}
      {rev && <Confirm danger title={`Revoke ${rev.label}?`} confirmLabel="Revoke" busy={busy}
        body={<><p>It will stop receiving context and its pending proposals are cancelled.</p><p className="fine">Responses already delivered to the assistant cannot be recalled.</p></>}
        onCancel={() => setRev(null)} onConfirm={revoke} />}
    </section>
  );
}
