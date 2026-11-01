import { useEffect, useRef, type ReactNode } from "react";

const CODES: Record<string, string> = {
  LOCKED: "The vault is locked. Unlock it to continue.",
  DENIED: "That action was not permitted.",
  CONFLICT: "This record changed since you opened it. Reload and review before saving.",
  INVALID_INPUT: "Some input was not accepted. Check the fields and try again.",
  STORAGE_ERROR: "The vault could not complete the storage operation.",
  CANCELLED: "Cancelled.",
  NOT_FOUND: "That item no longer exists.",
  KEYCHAIN_ERROR: "macOS could not approve access to the Keychain item. Nothing was unlocked.",
  WINDOWS_SECURITY_ERROR: "Windows could not protect or access the local credential. No plaintext fallback is used.",
  OWNER_VERIFICATION_UNAVAILABLE: "Windows Hello owner verification is unavailable. Set up Windows Hello on Windows 11; the vault stays locked.",
  OWNER_VERIFICATION_DENIED: "Owner verification was cancelled, failed, or invalidated by a session change. The vault stays locked.",
  UNSAFE_PATH: "This location is redirected or cannot be verified as private. Choose a local, non-redirected NTFS location.",
  LOCK_MONITOR_UNAVAILABLE: "The native lock monitor is unavailable. Restart the desktop app; the vault stays locked.",
  ENCRYPTION_UNAVAILABLE: "SQLCipher is unavailable. Alexandria refuses to use unencrypted storage.",
  LIMIT_EXCEEDED: "This operation exceeds the prototype's size or request limit.",
  FILE_EXISTS: "Choose new filenames. Existing exports, keys and backups are never overwritten.",
  NO_PENDING_IMPORT: "That preview expired or was cleared. Choose the file again.",
  UNSUPPORTED_VERSION: "This file or vault version is not supported.",
  BROKEN_VERSION_CHAIN: "The imported record history is incomplete or inconsistent.",
  INVALID_RECOVERY_KEY: "The recovery identity cannot open this backup.",
  INVALID_BACKUP: "The backup is invalid or corrupted. Your existing vault was not changed.",
  SCOPE_CHANGE_REQUIRES_NEW_RECORD: "A shared record cannot be moved between scopes. Create a separate record instead.",
};
export function errorText(e: unknown): string {
  const raw = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  for (const code of Object.keys(CODES)) if (raw.includes(code)) return CODES[code];
  if (raw.startsWith("Open the native Alexandria")) return raw;
  return "The vault operation failed.";
}
export const isCancelled = (e: unknown) => e instanceof Error && e.message.includes("CANCELLED");

export function Notice({ tone = "info", children, onDismiss }: { tone?: "info" | "warn" | "error"; children: ReactNode; onDismiss?: () => void }) {
  return (
    <div className={`notice notice-${tone}`} role={tone === "error" ? "alert" : "status"}>
      <div>{children}</div>
      {onDismiss && <button className="link" onClick={onDismiss}>Dismiss</button>}
    </div>
  );
}

export function Confirm({ title, body, confirmLabel, danger, busy, onConfirm, onCancel }: {
  title: string; body: ReactNode; confirmLabel: string; danger?: boolean; busy?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  const ref = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    ref.current?.focus();
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onCancel(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onCancel]);
  return (
    <div className="scrim" onMouseDown={onCancel}>
      <div className="dialog" role="alertdialog" aria-modal="true" aria-label={title} onMouseDown={(e) => e.stopPropagation()}>
        <h3>{title}</h3>
        <div className="dialog-body">{body}</div>
        <div className="row end">
          <button ref={ref} className="btn ghost" onClick={onCancel}>Cancel</button>
          <button className={`btn ${danger ? "danger" : "primary"}`} disabled={busy} onClick={onConfirm}>{busy ? "Working…" : confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

export function Skeleton({ rows = 4 }: { rows?: number }) {
  return <div className="skel-list" aria-busy="true">{Array.from({ length: rows }, (_, i) => <div key={i} className="skel" style={{ animationDelay: `${i * 90}ms` }} />)}</div>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><div className="empty-mark" /><h3>{title}</h3>{children && <p>{children}</p>}</div>;
}

export function fmt(d: string | null | undefined) {
  if (!d) return "—";
  const t = new Date(d);
  return isNaN(t.getTime()) ? d : t.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
