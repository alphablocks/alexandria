import { useState } from "react";
import { command, type Proposal } from "./api";
import { Empty, Notice, Skeleton, errorText, fmt } from "./ui";

export default function Review({ proposals, reload }: { proposals: Proposal[] | null; reload: () => Promise<void> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState("");
  async function resolve(id: string, approve: boolean) {
    setBusy(id); setErr("");
    try { await command("resolve", { id, approve }); await reload(); }
    catch (e) { setErr(errorText(e)); } finally { setBusy(null); }
  }
  const pending = (proposals ?? []).filter((p) => p.state.trim().toLowerCase() === "pending");
  return (
    <section className="pane solo">
      <div className="pane-head"><h2>Review</h2><span className="meta">Nothing is saved until you approve it.</span></div>
      {err && <Notice tone="error" onDismiss={() => setErr("")}>{err}</Notice>}
      {!proposals ? <Skeleton /> : pending.length === 0 ? <Empty title="No proposals waiting">When a connected assistant suggests something to remember, it appears here.</Empty> : (
        <div className="cards">
          {pending.map((p) => (
            <article key={p.id} className="card">
              <div className="meta">From <b>{p.connection_label}</b> · {fmt(p.created_at)}</div>
              <p className="body-text">{p.payload.text}</p>
              <dl className="facts">
                <div><dt>Destination</dt><dd>{p.payload.scope}{p.payload.kind ? ` · ${p.payload.kind}` : ""}</dd></div>
                <div><dt>Type</dt><dd className={p.payload.source.completeness === "summary" ? "tag" : ""}>{p.payload.source.completeness}</dd></div>
                <div><dt>Source</dt><dd>{p.payload.source.provider} · {p.payload.source.capture_method}</dd></div>
                {p.payload.source.reference && <div><dt>Reference</dt><dd className="mono">{p.payload.source.reference}</dd></div>}
                {p.payload.record_id && <div><dt>Updates</dt><dd className="mono">{p.payload.record_id} @ v{p.payload.expected_version ?? "?"}</dd></div>}
              </dl>
              <p className="fine">"{p.connection_label}" is a label for a paired installation, not proof of which app sent this.</p>
              <div className="row end">
                <button className="btn ghost" disabled={busy === p.id} onClick={() => resolve(p.id, false)}>Reject</button>
                <button className="btn primary" disabled={busy === p.id} onClick={() => resolve(p.id, true)}>Approve</button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
