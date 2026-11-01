//! A dedicated message-pump thread observes real WTS session and power events.
use crate::{check, wide, Error, Result};
use std::{
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    System::{LibraryLoader::GetModuleHandleW, RemoteDesktop::*},
    UI::WindowsAndMessaging::*,
};
#[derive(Clone)]
pub struct Signals {
    pub ready: Arc<AtomicBool>,
    pub epoch: Arc<AtomicU64>,
}
impl Signals {
    pub fn new(ready: Arc<AtomicBool>) -> Self {
        Self {
            ready,
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }
}
struct Context {
    signals: Signals,
    on_lock: Arc<dyn Fn() + Send + Sync>,
    session_locked: bool,
    suspended: bool,
}
impl Context {
    fn lock(&mut self) {
        self.signals.ready.store(false, Ordering::SeqCst);
        self.signals.epoch.fetch_add(1, Ordering::SeqCst);
        (self.on_lock)();
    }
    fn refresh(&self) {
        self.signals
            .ready
            .store(!self.session_locked && !self.suspended, Ordering::SeqCst);
    }
}
pub fn is_lock_event(msg: u32, w: usize) -> bool {
    (msg == WM_WTSSESSION_CHANGE
        && matches!(
            w as u32,
            WTS_SESSION_LOCK | WTS_SESSION_LOGOFF | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT
        ))
        || (msg == WM_POWERBROADCAST && w as u32 == PBT_APMSUSPEND)
}
fn unlocked() -> Result<bool> {
    unsafe {
        let mut p = ptr::null_mut();
        let mut size = 0;
        check(
            WTSQuerySessionInformationW(
                ptr::null_mut(),
                WTS_CURRENT_SESSION,
                WTSSessionInfoEx,
                &mut p,
                &mut size,
            ) != 0,
            "LOCK_MONITOR_UNAVAILABLE",
        )?;
        if size < std::mem::size_of::<WTSINFOEXW>() as u32 {
            WTSFreeMemory(p.cast());
            return Err(Error("LOCK_MONITOR_UNAVAILABLE"));
        }
        let info = &*(p as *const WTSINFOEXW);
        let valid = info.Level == 1;
        let flags = info.Data.WTSInfoExLevel1.SessionFlags;
        WTSFreeMemory(p.cast());
        check(
            valid
                && (flags == WTS_SESSIONSTATE_LOCK as i32
                    || flags == WTS_SESSIONSTATE_UNLOCK as i32),
            "LOCK_MONITOR_UNAVAILABLE",
        )?;
        Ok(flags == WTS_SESSIONSTATE_UNLOCK as i32)
    }
}
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == WM_NCCREATE {
        let create = &*(l as *const CREATESTRUCTW);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
    }
    let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Context;
    if !p.is_null() {
        let ctx = &mut *p;
        if is_lock_event(msg, w) {
            if msg == WM_WTSSESSION_CHANGE {
                ctx.session_locked = true;
            } else {
                ctx.suspended = true;
            }
            ctx.lock();
        } else if msg == WM_WTSSESSION_CHANGE
            && matches!(
                w as u32,
                WTS_SESSION_UNLOCK | WTS_SESSION_LOGON | WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT
            )
        {
            // Unlock notifications only reopen the gate, never the database.
            if let Ok(value) = unlocked() {
                ctx.session_locked = !value;
                ctx.refresh();
            } else {
                ctx.lock();
            }
        } else if msg == WM_POWERBROADCAST
            && matches!(w as u32, PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND)
        {
            ctx.suspended = false;
            if let Ok(value) = unlocked() {
                ctx.session_locked = !value;
                ctx.refresh();
            } else {
                ctx.lock();
            }
        } else if msg == WM_DESTROY {
            ctx.lock();
            PostQuitMessage(0);
        }
    }
    DefWindowProcW(hwnd, msg, w, l)
}
pub fn start(signals: Signals, on_lock: Arc<dyn Fn() + Send + Sync>) {
    std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            let mut ctx = Box::new(Context {
                signals: signals.clone(),
                on_lock: on_lock.clone(),
                session_locked: !unlocked()?,
                suspended: false,
            });
            unsafe {
                let name = wide("Alexandria.Vault.LockMonitor");
                let instance = GetModuleHandleW(ptr::null());
                let class = WNDCLASSW {
                    lpfnWndProc: Some(wndproc),
                    hInstance: instance,
                    lpszClassName: name.as_ptr(),
                    ..std::mem::zeroed()
                };
                check(RegisterClassW(&class) != 0, "LOCK_MONITOR_UNAVAILABLE")?;
                // A hidden top-level window receives WM_POWERBROADCAST; a
                // message-only HWND would miss broadcasts.
                let hwnd = CreateWindowExW(
                    0,
                    name.as_ptr(),
                    name.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    instance,
                    (&mut *ctx as *mut Context).cast(),
                );
                check(!hwnd.is_null(), "LOCK_MONITOR_UNAVAILABLE")?;
                if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
                    DestroyWindow(hwnd);
                    return Err(Error("LOCK_MONITOR_UNAVAILABLE"));
                }
                ctx.refresh();
                let mut msg = std::mem::zeroed();
                while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                signals.ready.store(false, Ordering::SeqCst);
                WTSUnRegisterSessionNotification(hwnd);
                if IsWindow(hwnd) != 0 {
                    DestroyWindow(hwnd);
                }
            }
            Ok(())
        })();
        let _ = result;
        signals.ready.store(false, Ordering::SeqCst);
        signals.epoch.fetch_add(1, Ordering::SeqCst);
        on_lock();
    });
}
