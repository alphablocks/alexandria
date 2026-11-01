import { useState } from "react";
import { command, type ImportPreview, type Status } from "./api";
import { Confirm, Notice, errorText, isCancelled } from "./ui";

export default function Locked({ status, onStatus }: { status: Status; onStatus: (s: Status) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [ask, setAsk] = useState(false);

  async function run(action: string) {
    setBusy(true); setErr("");
    try { onStatus(await command<Status>(action)); }
    catch (e) { if (!isCancelled(e)) setErr(errorText(e)); }
    finally { setBusy(false); }
  }
  async function pickRestore() {
    setBusy(true); setErr("");
    try { setPreview(await command<ImportPreview>("restore_dialog")); }
    catch (e) { if (!isCancelled(e)) setErr(errorText(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="gate">
      <div className="gate-card">
        <div className="mark">A</div>
        <h1>{status.initialized ? "Your vault is locked" : "Start your vault"}</h1>
        <p className="lede">
          {status.initialized
            ? "Unlocking asks your operating system for owner approval. Windows requires Windows Hello. This window never receives the vault key."
            : "Alexandria keeps your context on this computer, encrypted. Nothing is shared until you choose records for a connection."}
        </p>
        {status.recovery_warning && <Notice tone="warn">{status.recovery_warning}</Notice>}
        {err && <Notice tone="error" onDismiss={() => setErr("")}>{err}</Notice>}

        {status.initialized ? (
          <button className="btn primary wide" disabled={busy} onClick={() => run("unlock")}>{busy ? "Waiting for approval…" : "Unlock vault"}</button>
        ) : preview ? (
          <div className="restore">
            <h3>Restore preview</h3>
            <dl className="stats">
              <div><dt>Records</dt><dd>{preview.records}</dd></div>
              <div><dt>Added</dt><dd>{preview.added}</dd></div>
              <div><dt>Duplicates</dt><dd>{preview.duplicates}</dd></div>
            </dl>
            {preview.conflicts.length > 0 && <Notice tone="error">This backup has {preview.conflicts.length} conflict(s) and cannot be restored.</Notice>}
            <p className="fine">A restored vault starts fresh: earlier connections, grants and pending proposals are not reactivated. An older backup may contain text you have since deleted.</p>
            <div className="row">
              <button className="btn ghost" disabled={busy} onClick={async () => { await command("import_cancel").catch(() => undefined); setPreview(null); }}>Back</button>
              <button className="btn primary" disabled={busy || preview.conflicts.length > 0} onClick={() => setAsk(true)}>Restore this backup</button>
            </div>
          </div>
        ) : (
          <>
            <button className="btn primary wide" disabled={busy} onClick={() => run("create")}>{busy ? "Working…" : "Create encrypted vault"}</button>
            <button className="btn ghost wide" disabled={busy} onClick={pickRestore}>Restore from encrypted backup</button>
            <p className="fine">No account, no sign-in. The recovery identity is handled by native dialogs; keep it somewhere separate from your backups.</p>
          </>
        )}
      </div>
      {ask && (
        <Confirm title="Restore into a new vault?" confirmLabel="Restore" busy={busy}
          body={<p>This creates your local vault from the selected backup. You will be asked for owner approval.</p>}
          onCancel={() => setAsk(false)}
          onConfirm={async () => { setAsk(false); setPreview(null); await run("restore_confirm"); }} />
      )}
    </div>
  );
}
