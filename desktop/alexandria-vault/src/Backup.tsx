import { useState } from "react";
import { command, type ImportPreview } from "./api";
import { Confirm, Notice, errorText, isCancelled } from "./ui";

export default function Backup({ reload }: { reload: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "info" | "error"; text: string } | null>(null);
  const [ask, setAsk] = useState<"export" | "backup" | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);

  async function run<T>(action: string, done?: (r: T) => void, ok?: string) {
    setBusy(true); setMsg(null);
    try { const r = await command<T>(action); done?.(r); if (ok) setMsg({ tone: "info", text: ok }); }
    catch (e) { if (!isCancelled(e)) setMsg({ tone: "error", text: errorText(e) }); }
    finally { setBusy(false); }
  }

  return (
    <section className="pane solo">
      <div className="pane-head"><h2>Backup and export</h2></div>
      {msg && <Notice tone={msg.tone} onDismiss={() => setMsg(null)}>{msg.text}</Notice>}
      <div className="blocks">
        <article className="block">
          <h3>Encrypted backup</h3>
          <p>A recovery file only your recovery identity can open. Use this to move to a new computer.</p>
          <button className="btn primary" disabled={busy} onClick={() => setAsk("backup")}>Create backup…</button>
        </article>
        <article className="block">
          <h3>Readable export</h3>
          <p>JSON and Markdown copies you can read or bring to another tool. These files are not encrypted.</p>
          <button className="btn ghost" disabled={busy} onClick={() => setAsk("export")}>Export…</button>
        </article>
        <article className="block">
          <h3>Import</h3>
          <p>Bring in an Alexandria export. Imported records start private.</p>
          {!preview ? <button className="btn ghost" disabled={busy} onClick={() => run<ImportPreview>("import_dialog", setPreview)}>Choose file…</button> : (
            <div className="restore">
              <dl className="stats">
                <div><dt>Records</dt><dd>{preview.records}</dd></div>
                <div><dt>Added</dt><dd>{preview.added}</dd></div>
                <div><dt>Duplicates</dt><dd>{preview.duplicates}</dd></div>
                <div><dt>Conflicts</dt><dd>{preview.conflicts.length}</dd></div>
              </dl>
              {preview.conflicts.length > 0 && (
                <Notice tone="error">Import blocked by conflicts:<ul className="conf">{preview.conflicts.slice(0, 20).map((c, i) => <li key={i} className="mono">{c}</li>)}</ul></Notice>
              )}
              <div className="row">
                <button className="btn ghost" disabled={busy} onClick={() => run("import_cancel", () => setPreview(null))}>Cancel</button>
                <button className="btn primary" disabled={busy || preview.conflicts.length > 0}
                  onClick={() => run("import_confirm", () => { setPreview(null); void reload(); }, "Import complete. New records are private.")}>Import {preview.added}</button>
              </div>
            </div>
          )}
        </article>
      </div>
      <p className="fine">Restoring a backup is only available when no vault exists on this computer. Deleting a memory does not change backups or exports you already made.</p>
      {ask === "export" && <Confirm title="Export plaintext?" confirmLabel="Choose location"
        body={<p>Anyone or any app with access to the exported files can read every exported memory. Alexandria cannot protect or delete these copies.</p>}
        onCancel={() => setAsk(null)} onConfirm={() => { setAsk(null); void run("export_dialog", undefined, "Export written."); }} />}
      {ask === "backup" && <Confirm title="Create encrypted backup" confirmLabel="Continue"
        body={<p>Keep the recovery identity separate from the backup file, ideally in a password manager or offline. Without it the backup cannot be opened. Alexandria has no reset.</p>}
        onCancel={() => setAsk(null)} onConfirm={() => { setAsk(null); void run("backup_dialog", undefined, "Encrypted backup written."); }} />}
    </section>
  );
}
