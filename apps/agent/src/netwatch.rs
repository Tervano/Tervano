//! Event-driven network change detection (T-210): Windows calls us when a unicast IP address is
//! added, removed or changed, so new addresses are reported within seconds instead of at the
//! next poll.

use std::sync::Arc;
use tokio::sync::Notify;

#[cfg(windows)]
pub struct NetWatch {
    handle: windows::Win32::Foundation::HANDLE,
    /// Raw pointer handed to Windows as the callback context; reclaimed in Drop.
    ctx: *const Notify,
}

// SAFETY: the handle is only used to cancel the registration, and the context is an Arc<Notify>
// (itself Send + Sync) that Windows reads from its own threads.
#[cfg(windows)]
unsafe impl Send for NetWatch {}

#[cfg(windows)]
unsafe extern "system" fn on_change(
    ctx: *const core::ffi::c_void,
    _row: *const windows::Win32::NetworkManagement::IpHelper::MIB_UNICASTIPADDRESS_ROW,
    _kind: windows::Win32::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: `ctx` is the Arc<Notify> pointer registered in `watch`, kept alive until
    // CancelMibChangeNotify2 has returned (which waits for in-flight callbacks).
    let notify = unsafe { &*(ctx as *const Notify) };
    notify.notify_one();
}

/// Starts watching; `notify` fires on every address change. `None` if registration fails, in
/// which case the poll interval still catches changes.
#[cfg(windows)]
pub fn watch(notify: Arc<Notify>) -> Option<NetWatch> {
    use windows::Win32::Foundation::{HANDLE, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::NotifyUnicastIpAddressChange;
    use windows::Win32::Networking::WinSock::AF_UNSPEC;
    let ctx = Arc::into_raw(notify);
    let mut handle = HANDLE::default();
    // SAFETY: the callback has the documented signature; `ctx` stays valid until Drop.
    let rc = unsafe {
        NotifyUnicastIpAddressChange(
            AF_UNSPEC,
            Some(on_change),
            Some(ctx.cast()),
            false,
            &mut handle,
        )
    };
    if rc != NO_ERROR {
        // SAFETY: registration failed, so Windows holds no copy of the pointer.
        drop(unsafe { Arc::from_raw(ctx) });
        tracing::warn!("network change notifications unavailable ({rc:?}); relying on polling");
        return None;
    }
    Some(NetWatch { handle, ctx })
}

#[cfg(windows)]
impl Drop for NetWatch {
    fn drop(&mut self) {
        // SAFETY: valid registration handle; the call blocks until running callbacks finish, so
        // afterwards nothing references `ctx` and it can be released.
        unsafe {
            let _ =
                windows::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(self.handle);
            drop(Arc::from_raw(self.ctx));
        }
    }
}

#[cfg(not(windows))]
pub struct NetWatch;

#[cfg(not(windows))]
pub fn watch(_notify: Arc<Notify>) -> Option<NetWatch> {
    // shortcut: no netlink watcher yet; polling covers non-Windows agents (T-957).
    None
}
