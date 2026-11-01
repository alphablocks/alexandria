import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Archive, Inbox, Library, Link2, Lock } from "lucide-react";
import { command, nativeAvailable, type Connection, type Proposal, type RecordItem, type Status } from "./api";
import { Notice, errorText } from "./ui";
import Locked from "./Locked";
import Memories from "./Memories";
import Review from "./Review";
import Connections from "./Connections";
import Backup from "./Backup";

type Tab = "memories" | "review" | "connections" | "backup";

function Vault({ onStatus, recoveryWarning }: { onStatus: (s: Status) => void; recoveryWarning?: string }) {
  const [tab, setTab] = useState<Tab>("memories");
  const [records, setRecords] = useState<RecordItem[] | null>(null);
  const [connections, setConnections] = useState<Connection[] | null>(null);
  const [proposals, setProposals] = useState<Proposal[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  const loadAll = useCallback(async () => {
    try {
      const [r, c, p] = await Promise.all([
        command<RecordItem[]>("list"), command<Connection[]>("connections"), command<Proposal[]>("proposals"),
      ]);
      if (!alive.current) return;
      setRecords(r); setConnections(c); setProposals(p); setErr("");
    } catch (e) { if (alive.current) setErr(errorText(e)); }
    finally { if (alive.current) setLoading(false); }
  }, []);
  const loadProposals = useCallback(async () => {
    try { const p = await command<Proposal[]>("proposals"); if (alive.current) setProposals(p); } catch { /* status poll decides lock */ }
  }, []);

  useEffect(() => {
    void loadAll();
    const t = window.setInterval(loadProposals, 8000);
    const f = () => void loadAll();
    window.addEventListener("focus", f);
    return () => { window.clearInterval(t); window.removeEventListener("focus", f); };
  }, [loadAll, loadProposals]);

  async function lock() {
    try { onStatus(await command<Status>("lock")); } catch (e) { setErr(errorText(e)); }
  }
  const pending = (proposals ?? []).filter((p) => p.state.trim().toLowerCase() === "pending").length;
  const nav: [Tab, string, typeof Library, number?][] = [
    ["memories", "Memories", Library], ["review", "Review", Inbox, pending], ["connections", "Connections", Link2], ["backup", "Backup", Archive],
  ];

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand"><div className="mark sm">A</div><span>Alexandria</span></div>
        <nav>
          {nav.map(([k, label, Icon, n]) => (
            <button key={k} className={`nav ${tab === k ? "on" : ""}`} onClick={() => setTab(k)}>
              <Icon size={16} /><span>{label}</span>{!!n && <em>{n}</em>}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <span className="meta">Unlocked on this computer</span>
          <button className="btn ghost wide" onClick={lock}><Lock size={14} /> Lock now</button>
        </div>
      </aside>
      <main className="main">
        {recoveryWarning && <Notice tone="warn">{recoveryWarning}</Notice>}
        {err && <Notice tone="error" onDismiss={() => setErr("")}>{err} <button className="link" onClick={() => void loadAll()}>Retry</button></Notice>}
        {tab === "memories" && <Memories records={records} connections={connections} loading={loading} reload={loadAll} />}
        {tab === "review" && <Review proposals={proposals} reload={loadAll} />}
        {tab === "connections" && <Connections connections={connections} records={records} reload={loadAll} />}
        {tab === "backup" && <Backup reload={loadAll} />}
      </main>
    </div>
  );
}

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [err, setErr] = useState("");
  const [session, setSession] = useState(0);
  const wasUnlocked = useRef(false);
  const latestEpoch = useRef(-1);

  const apply = useCallback((s: Status) => {
    if (s.epoch < latestEpoch.current) return;
    latestEpoch.current = s.epoch;
    if (s.unlocked && !wasUnlocked.current) setSession((n) => n + 1);
    wasUnlocked.current = s.unlocked;
    setStatus(s);
  }, []);
  const refresh = useCallback(async () => {
    try { apply(await command<Status>("status")); setErr(""); }
    catch (e) {
      // Fail closed: any status error hides vault contents.
      wasUnlocked.current = false;
      setStatus((s) => s && { ...s, unlocked: false });
      setErr(errorText(e));
    }
  }, [apply]);

  useEffect(() => {
    if (!nativeAvailable) return;
    void refresh();
    const t = window.setInterval(refresh, 4000);
    const f = () => void refresh();
    window.addEventListener("focus", f);
    document.addEventListener("visibilitychange", f);
    return () => { window.clearInterval(t); window.removeEventListener("focus", f); document.removeEventListener("visibilitychange", f); };
  }, [refresh]);

  useEffect(() => {
    if (!nativeAvailable) return;
    let disposed = false;
    const subscription = listen<Status | null>("vault-locked", ({ payload }) => {
      if (payload) apply(payload);
      else {
        wasUnlocked.current = false;
        setStatus((s) => s && { ...s, unlocked: false });
      }
    });
    void subscription.then((unlisten) => { if (disposed) unlisten(); }).catch(() => void refresh());
    return () => { disposed = true; void subscription.then((unlisten) => unlisten()).catch(() => undefined); };
  }, [refresh, apply]);

  // Owner activity only: real, trusted pointer/keyboard events, throttled.
  useEffect(() => {
    if (!nativeAvailable) return;
    let last = 0;
    const on = (e: Event) => {
      if (!e.isTrusted || !wasUnlocked.current) return;
      const now = Date.now();
      if (now - last < 30000) return;
      last = now;
      command("touch").catch(() => undefined);
    };
    window.addEventListener("pointerdown", on, true);
    window.addEventListener("keydown", on, true);
    return () => { window.removeEventListener("pointerdown", on, true); window.removeEventListener("keydown", on, true); };
  }, []);

  if (!nativeAvailable) {
    return (
      <div className="gate"><div className="gate-card">
        <div className="mark">A</div>
        <h1>Open the desktop app</h1>
        <p className="lede">This browser cannot reach your encrypted vault. Alexandria only runs inside its native window, so nothing is shown here.</p>
      </div></div>
    );
  }
  if (!status) {
    return <div className="gate"><div className="gate-card">{err ? <Notice tone="error">{err} <button className="link" onClick={() => void refresh()}>Retry</button></Notice> : <div className="skel tall" />}</div></div>;
  }
  if (!status.unlocked) return <Locked status={status} onStatus={apply} />;
  return <Vault key={session} onStatus={apply} recoveryWarning={status.recovery_warning} />;
}
