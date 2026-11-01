import { useMemo, useState } from "react";
import { Plus, Search, History, Trash2, X } from "lucide-react";
import { command, type Connection, type RecordItem } from "./api";
import { Confirm, Empty, Notice, Skeleton, errorText, fmt } from "./ui";

type Draft = { id?: string; expected_version?: number; text: string; scope: string; kind: string; sensitivity: string;
  provider: string; capture_method: string; reference: string; completeness: string };
const blank: Draft = { text: "", scope: "personal", kind: "user_statement", sensitivity: "ordinary", provider: "owner", capture_method: "explicit_save", reference: "owner:manual", completeness: "selected_excerpt" };

export default function Memories({ records, connections, loading, reload }: {
  records: RecordItem[] | null; connections: Connection[] | null; loading: boolean; reload: () => Promise<void>;
}) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [history, setHistory] = useState<RecordItem[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [del, setDel] = useState<RecordItem | null>(null);

  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (records ?? []).filter((r) => !s || [r.text, r.scope, r.kind, r.source.provider].some((v) => v.toLowerCase().includes(s)));
  }, [records, q]);
  const current = records?.find((r) => r.id === sel) ?? null;
  const recipients = (id?: string) => id ? (connections ?? []).filter((c) => !c.revoked && c.record_ids.includes(id)) : [];

  function open(r: RecordItem) { setSel(r.id); setDraft(null); setHistory(null); setErr(""); }
  function edit(r: RecordItem) {
    setDraft({ id: r.id, expected_version: r.version, text: r.text, scope: r.scope, kind: r.kind, sensitivity: r.sensitivity, ...r.source });
  }
  async function save() {
    if (!draft) return;
    setBusy(true); setErr("");
    const { provider, capture_method, reference, completeness, ...rest } = draft;
    try {
      const saved = await command<RecordItem>("save", { ...rest, source: { provider, capture_method, reference, completeness } });
      setDraft(null); setSel(saved.id); setHistory(null); await reload();
    } catch (e) { setErr(errorText(e)); } finally { setBusy(false); }
  }
  async function loadHistory(id: string) {
    setErr("");
    try { setHistory(await command<RecordItem[]>("history", { id })); } catch (e) { setErr(errorText(e)); }
  }
  async function remove() {
    if (!del) return;
    setBusy(true);
    try { await command("delete", { id: del.id }); setDel(null); setSel(null); await reload(); }
    catch (e) { setErr(errorText(e)); setDel(null); } finally { setBusy(false); }
  }
  const set = (k: keyof Draft) => (e: { target: { value: string } }) => setDraft((d) => d && { ...d, [k]: e.target.value });

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-head">
          <h2>Memories</h2>
          <button className="btn primary sm" onClick={() => { setSel(null); setHistory(null); setDraft({ ...blank }); }}><Plus size={14} /> New</button>
        </div>
        <label className="search"><Search size={14} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search this vault" /></label>
        {loading && !records ? <Skeleton rows={6} /> : list.length === 0 ? (
          <Empty title={q ? "No matches" : "Nothing saved yet"}>{q ? "Try a different word." : "Write your first memory, or approve one from Review."}</Empty>
        ) : (
          <ul className="rows">
            {list.map((r) => (
              <li key={r.id}>
                <button className={`rowbtn ${sel === r.id ? "on" : ""}`} onClick={() => open(r)}>
                  <span className="clip">{r.text}</span>
                  <span className="meta">{r.scope} · {r.kind} · v{r.version}{recipients(r.id).length > 0 && <> · <b>{recipients(r.id).length} shared</b></>}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="pane detail">
        {err && <Notice tone="error" onDismiss={() => setErr("")}>{err}</Notice>}
        {draft ? (
          <div className="editor">
            <div className="pane-head"><h2>{draft.id ? "Edit memory" : "New memory"}</h2><button className="icon" aria-label="Close" onClick={() => setDraft(null)}><X size={16} /></button></div>
            {draft.id && (
              <Notice tone={recipients(draft.id).length ? "warn" : "info"}>
                {recipients(draft.id).length
                  ? <>Saving sends the corrected version to: <b>{recipients(draft.id).map((c) => c.label).join(", ")}</b>.</>
                  : "This record is private. No connection can read it."}
              </Notice>
            )}
            <textarea value={draft.text} onChange={set("text")} rows={10} placeholder="Exact text to remember" />
            <div className="grid">
              <label>Scope<input value={draft.scope} onChange={set("scope")} disabled={!!draft.id} /></label>
              <label>Kind<select value={draft.kind} onChange={set("kind")}><option value="user_statement">User statement</option><option value="assistant_inference">Assistant inference</option><option value="source_excerpt">Source excerpt</option></select></label>
              <label>Sensitivity<select value={draft.sensitivity} onChange={set("sensitivity")}><option value="ordinary">ordinary</option><option value="sensitive">sensitive</option></select></label>
              <label>Completeness<select value={draft.completeness} onChange={set("completeness")}><option value="selected_excerpt">selected excerpt</option><option value="summary">summary</option></select></label>
              <label>Source provider<input value={draft.provider} onChange={set("provider")} /></label>
              <label>Capture method<input value={draft.capture_method} onChange={set("capture_method")} /></label>
              <label className="span2">Source reference<input value={draft.reference} onChange={set("reference")} placeholder="Source label, shown as text only" /></label>
            </div>
            <div className="row end">
              <button className="btn ghost" onClick={() => setDraft(null)}>Cancel</button>
              <button className="btn primary" disabled={busy || !draft.text.trim() || !draft.scope.trim() || !draft.reference.trim() || !draft.provider.trim() || !draft.capture_method.trim()} onClick={save}>{busy ? "Saving…" : "Save"}</button>
            </div>
          </div>
        ) : current ? (
          <article>
            <div className="pane-head">
              <span className="meta">{current.scope} · {current.kind} · version {current.version} · {current.status}</span>
              <div className="row">
                <button className="btn ghost sm" onClick={() => loadHistory(current.id)}><History size={14} /> History</button>
                <button className="btn ghost sm" onClick={() => edit(current)}>Edit</button>
                <button className="btn ghost sm danger-text" onClick={() => setDel(current)}><Trash2 size={14} /> Delete</button>
              </div>
            </div>
            <p className="body-text">{current.text}</p>
            <dl className="facts">
              <div><dt>Source</dt><dd>{current.source.provider} · {current.source.capture_method} · {current.source.completeness}</dd></div>
              {current.source.reference && <div><dt>Reference</dt><dd className="mono">{current.source.reference}</dd></div>}
              <div><dt>Sensitivity</dt><dd>{current.sensitivity}</dd></div>
              <div><dt>Updated</dt><dd>{fmt(current.updated_at)}</dd></div>
              <div><dt>Approved</dt><dd>{fmt(current.approved_at)}</dd></div>
              <div><dt>Shared with</dt><dd>{recipients(current.id).map((c) => c.label).join(", ") || "Nobody. Private."}</dd></div>
            </dl>
            {history && (
              <div className="history">
                <h3>History</h3>
                {history.length === 0 ? <p className="fine">No earlier versions.</p> : history.map((h) => (
                  <div key={`${h.id}-${h.version}`} className="hist"><span className="meta">v{h.version} · {fmt(h.updated_at)} · {h.status}</span><p>{h.text}</p></div>
                ))}
              </div>
            )}
          </article>
        ) : <Empty title="Select a memory">Everything here is exact text you saved or approved.</Empty>}
      </section>

      {del && <Confirm danger title="Delete this memory?" confirmLabel="Delete" busy={busy}
        body={<><p>Removes the text, its history and pending proposals from this vault.</p><p className="fine">Existing backups, exports and provider conversations are separate copies and are not changed.</p></>}
        onCancel={() => setDel(null)} onConfirm={remove} />}
    </div>
  );
}
