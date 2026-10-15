//! Windows service inspection and control for background administration (PLAN §7, T-701).

use tervano_protocol::{ServiceAction, ServiceEntry, StartType};

/// The agent's own service name: never stopped or disabled remotely, or the technician locks
/// themselves out of the machine.
const SELF_SERVICE: &str = "TervanoAgent";

fn validate_name(name: &str) -> Result<(), String> {
    // Service key names cannot contain slashes and are at most 256 characters.
    if name.is_empty() || name.len() > 256 || name.contains(['/', '\\']) {
        return Err(format!("invalid service name {name:?}"));
    }
    Ok(())
}

fn guard_self(name: &str, what: &str) -> Result<(), String> {
    if name.eq_ignore_ascii_case(SELF_SERVICE) {
        return Err(format!(
            "refusing to {what} the Tervano Agent service: it would end remote management of this computer"
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub use platform::{control, list, set_start_type};

#[cfg(windows)]
mod platform {
    use super::*;
    use std::time::{Duration, Instant};
    use windows::Win32::System::Services::{
        ChangeServiceConfigW, CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE,
        EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
        SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACCEPT_PAUSE_CONTINUE,
        SERVICE_ACCEPT_STOP, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_CONTINUE_PENDING,
        SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_ERROR, SERVICE_NO_CHANGE,
        SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATE_ALL, SERVICE_STATUS_CURRENT_STATE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
        SERVICE_WIN32,
    };
    use windows::core::{HSTRING, PCWSTR};
    use windows_service::service::{
        ServiceAccess, ServiceDependency, ServiceStartType, ServiceState,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    /// SC_HANDLE that closes itself.
    struct Handle(SC_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: we own the handle and close it exactly once.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }

    fn state_name(s: SERVICE_STATUS_CURRENT_STATE) -> &'static str {
        match s {
            SERVICE_RUNNING => "running",
            SERVICE_STOPPED => "stopped",
            SERVICE_PAUSED => "paused",
            SERVICE_START_PENDING => "start_pending",
            SERVICE_STOP_PENDING => "stop_pending",
            SERVICE_PAUSE_PENDING => "pause_pending",
            SERVICE_CONTINUE_PENDING => "continue_pending",
            _ => "unknown",
        }
    }

    /// windows-service's Display hides the OS reason ("IO error in winapi call"); show it instead.
    fn ws(e: windows_service::Error) -> String {
        match e {
            windows_service::Error::Winapi(io) => io.to_string(),
            other => other.to_string(),
        }
    }

    fn manager() -> Result<ServiceManager, String> {
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| format!("cannot open the service manager: {}", ws(e)))
    }

    /// Lists Win32 services (not drivers), with configuration where readable.
    pub fn list() -> Result<Vec<ServiceEntry>, String> {
        // SAFETY: no pointer arguments; the handle is closed by `Handle`.
        let scm = Handle(
            unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) }
                .map_err(|e| format!("cannot open the service manager: {e}"))?,
        );
        // u64 storage keeps the buffer 8-byte aligned for ENUM_SERVICE_STATUS_PROCESSW.
        let mut buf: Vec<u64> = vec![0; 64 * 1024 / 8];
        let mut out = Vec::new();
        let mut resume = 0u32;
        loop {
            let (mut needed, mut count) = (0u32, 0u32);
            // SAFETY: `buf` is valid for its byte length; out-params point to live locals.
            let r = unsafe {
                EnumServicesStatusExW(
                    scm.0,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    Some(std::slice::from_raw_parts_mut(
                        buf.as_mut_ptr().cast::<u8>(),
                        buf.len() * 8,
                    )),
                    &mut needed,
                    &mut count,
                    Some(&mut resume),
                    PCWSTR::null(),
                )
            };
            // SAFETY: the API wrote `count` entries at the start of the aligned buffer.
            let entries = unsafe {
                std::slice::from_raw_parts(
                    buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                    count as usize,
                )
            };
            for e in entries {
                // SAFETY: the name pointers point into `buf`, which is alive here.
                let (name, display) = unsafe {
                    (
                        e.lpServiceName.to_string().unwrap_or_default(),
                        e.lpDisplayName.to_string().unwrap_or_default(),
                    )
                };
                let st = e.ServiceStatusProcess;
                out.push(ServiceEntry {
                    display_name: display,
                    state: state_name(st.dwCurrentState).into(),
                    pid: (st.dwProcessId != 0).then_some(st.dwProcessId),
                    can_stop: st.dwControlsAccepted & SERVICE_ACCEPT_STOP != 0,
                    can_pause: st.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE != 0,
                    start_type: None,
                    account: None,
                    executable: None,
                    dependencies: Vec::new(),
                    name,
                });
            }
            match r {
                Ok(()) => break,
                // More entries: continue from `resume`, growing the buffer if one entry didn't fit.
                Err(e) if e.code() == windows::Win32::Foundation::ERROR_MORE_DATA.to_hresult() => {
                    if count == 0 {
                        buf.resize((needed as usize).div_ceil(8) + 1, 0);
                    }
                }
                Err(e) => return Err(format!("enumerating services failed: {e}")),
            }
        }
        let mgr = manager()?;
        for s in &mut out {
            fill_config(&mgr, s);
        }
        out.sort_by_key(|s| s.display_name.to_lowercase());
        Ok(out)
    }

    fn fill_config(mgr: &ServiceManager, s: &mut ServiceEntry) {
        let Ok(svc) = mgr.open_service(&s.name, ServiceAccess::QUERY_CONFIG) else {
            return;
        };
        let Ok(cfg) = svc.query_config() else {
            return;
        };
        s.start_type = Some(match cfg.start_type {
            ServiceStartType::AutoStart => StartType::Automatic,
            ServiceStartType::OnDemand => StartType::Manual,
            ServiceStartType::Disabled => StartType::Disabled,
            ServiceStartType::BootStart => StartType::Boot,
            ServiceStartType::SystemStart => StartType::System,
        });
        s.account = cfg.account_name.map(|a| a.to_string_lossy().into_owned());
        s.executable = Some(cfg.executable_path.display().to_string());
        s.dependencies = cfg
            .dependencies
            .iter()
            .map(|d| match d {
                ServiceDependency::Service(n) => n.to_string_lossy().into_owned(),
                ServiceDependency::Group(g) => format!("group:{}", g.to_string_lossy()),
            })
            .collect();
    }

    fn one(name: &str) -> Result<ServiceEntry, String> {
        list()?
            .into_iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("service {name} not found"))
    }

    /// Waits for a pending state to settle (SCM operations are asynchronous).
    fn wait_for(
        svc: &windows_service::service::Service,
        want: ServiceState,
        limit: Duration,
    ) -> Result<(), String> {
        let start = Instant::now();
        loop {
            let st = svc.query_status().map_err(ws)?.current_state;
            if st == want {
                return Ok(());
            }
            if start.elapsed() > limit {
                return Err(format!(
                    "timed out waiting for the service to become {want:?} (now {st:?})"
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    pub fn control(name: &str, action: ServiceAction) -> Result<ServiceEntry, String> {
        validate_name(name)?;
        if matches!(
            action,
            ServiceAction::Stop | ServiceAction::Pause | ServiceAction::Restart
        ) {
            guard_self(name, "stop or pause")?;
        }
        let mgr = manager()?;
        let svc = mgr
            .open_service(
                name,
                ServiceAccess::QUERY_STATUS
                    | ServiceAccess::START
                    | ServiceAccess::STOP
                    | ServiceAccess::PAUSE_CONTINUE,
            )
            .map_err(|e| format!("cannot open service {name}: {}", ws(e)))?;
        let limit = Duration::from_secs(30);
        let r = match action {
            ServiceAction::Start => svc
                .start::<&str>(&[])
                .map_err(ws)
                .and_then(|()| wait_for(&svc, ServiceState::Running, limit)),
            ServiceAction::Stop => svc
                .stop()
                .map_err(ws)
                .and_then(|_| wait_for(&svc, ServiceState::Stopped, limit)),
            ServiceAction::Pause => svc
                .pause()
                .map_err(ws)
                .and_then(|_| wait_for(&svc, ServiceState::Paused, limit)),
            ServiceAction::Resume => svc
                .resume()
                .map_err(ws)
                .and_then(|_| wait_for(&svc, ServiceState::Running, limit)),
            ServiceAction::Restart => svc
                .stop()
                .map_err(ws)
                .and_then(|_| wait_for(&svc, ServiceState::Stopped, limit))
                .and_then(|()| svc.start::<&str>(&[]).map_err(ws))
                .and_then(|()| wait_for(&svc, ServiceState::Running, limit)),
        };
        r.map_err(|e| format!("{action:?} {name} failed: {e}"))?;
        one(name)
    }

    pub fn set_start_type(name: &str, start: StartType) -> Result<ServiceEntry, String> {
        validate_name(name)?;
        let raw = match start {
            StartType::Automatic => SERVICE_AUTO_START,
            StartType::Manual => SERVICE_DEMAND_START,
            StartType::Disabled => {
                guard_self(name, "disable")?;
                SERVICE_DISABLED
            }
            StartType::Boot | StartType::System => {
                return Err("boot/system start types apply to drivers and are not settable".into());
            }
        };
        // SAFETY: no pointer arguments; handles are closed by `Handle`.
        let scm = Handle(
            unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }
                .map_err(|e| format!("cannot open the service manager: {e}"))?,
        );
        // SAFETY: `scm` is valid; the name is a valid wide string for the call.
        let svc = Handle(
            unsafe { OpenServiceW(scm.0, &HSTRING::from(name), SERVICE_CHANGE_CONFIG) }
                .map_err(|e| format!("cannot open service {name}: {e}"))?,
        );
        // Only the start type changes; SERVICE_NO_CHANGE / null leave every other field intact.
        // SAFETY: `svc` is valid; null PCWSTRs mean "no change".
        unsafe {
            ChangeServiceConfigW(
                svc.0,
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                raw,
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                PCWSTR::null(),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        }
        .map_err(|e| format!("changing start type of {name} failed: {e}"))?;
        one(name)
    }
}

#[cfg(not(windows))]
mod unsupported {
    use super::*;
    const MSG: &str = "service management is only implemented on Windows";
    pub fn list() -> Result<Vec<ServiceEntry>, String> {
        Err(MSG.into())
    }
    pub fn control(name: &str, _: ServiceAction) -> Result<ServiceEntry, String> {
        validate_name(name)?;
        guard_self(name, "control")?;
        Err(MSG.into())
    }
    pub fn set_start_type(_: &str, _: StartType) -> Result<ServiceEntry, String> {
        Err(MSG.into())
    }
}
#[cfg(not(windows))]
pub use unsupported::{control, list, set_start_type};
