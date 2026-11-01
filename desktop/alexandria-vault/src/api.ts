import { invoke, isTauri } from "@tauri-apps/api/core";
export type Source = {provider:string;capture_method:string;reference:string;completeness:string};
export type RecordItem = {
  id:string;version:number;scope:string;kind:string;text:string;status:string;
  source:Source;created_at:string;updated_at:string;approved_at:string|null;
  supersedes:{id:string;version:number}|null;sensitivity:string;
};
export type Connection = {id:string;label:string;revoked:boolean;write_scope:string|null;record_ids:string[]};
export type Proposal = {id:string;connection_id:string;connection_label:string;state:string;payload:{text:string;scope:string;kind?:string;source:Source;record_id?:string;expected_version?:number};created_at:string};
export type Status = {initialized:boolean;unlocked:boolean;native:boolean;epoch:number;recovery_warning?:string};
export type ImportPreview = {added:number;duplicates:number;records:number;conflicts:string[];restore?:boolean};
export const nativeAvailable = isTauri();
// No browser fallback, sample records, localStorage or network store.
export async function command<T=unknown>(action:string,payload:object={}):Promise<T> {
  if(!nativeAvailable) throw new Error("Open the native Alexandria desktop app. This browser cannot access your encrypted vault.");
  try { return await invoke<T>("vault_command",{action,payload}); }
  catch(error) { throw new Error(typeof error==="string"? error : "The vault operation failed."); }
}
// Native command contract:
// status -> Status; create/unlock/lock -> Status.
// list -> RecordItem[]; history {id} -> RecordItem[];
// save {text,scope,kind,sensitivity,source,id?,expected_version?} -> RecordItem;
// delete {id} -> {status}; connections -> Connection[];
// pair {label} -> {id,label} (credentials NEVER returned to renderer);
// grant {id,record_ids,write_scope:null|string} -> {status}; revoke {id} -> {status};
// proposals -> Proposal[]; resolve {id,approve:boolean} -> {status,record?};
// export_dialog -> {status}; import_dialog -> ImportPreview;
// import_confirm -> {status}; import_cancel -> {status};
// backup_dialog -> {status}; restore_dialog -> ImportPreview; restore_confirm -> Status.
// touch -> {status} (only real owner keyboard/pointer input); errors are sanitized codes.
