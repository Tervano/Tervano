//! Process inspection and termination for background administration (PLAN §7, T-700).

use std::collections::HashMap;
use std::sync::Mutex;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tervano_protocol::{KillRequest, ProcessInfo};

pub struct Processes {
    /// Kept between listings so CPU usage is measured over the interval since the last one.
    sys: Mutex<System>,
    /// SID → account name. Domain SIDs can cost a domain-controller round trip, so resolve once.
    owners: Mutex<HashMap<String, Option<String>>>,
}

fn refresh(sys: &mut System) {
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet),
    );
}

impl Processes {
    pub fn new() -> Self {
        Self {
            sys: Mutex::new(System::new()),
            owners: Mutex::new(HashMap::new()),
        }
    }

    pub fn list(&self) -> Vec<ProcessInfo> {
        let mut sys = self.sys.lock().expect("not poisoned");
        if sys.processes().is_empty() {
            // CPU usage needs two samples; the first listing waits for the minimum interval.
            refresh(&mut sys);
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        }
        refresh(&mut sys);
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get()) as f32;
        let mut owners = self.owners.lock().expect("not poisoned");
        let mut out: Vec<ProcessInfo> = sys
            .processes()
            .values()
            .map(|p| {
                let user = p.user_id().and_then(|uid| {
                    let sid = uid.to_string();
                    owners
                        .entry(sid)
                        .or_insert_with_key(|sid| platform::account_name(sid))
                        .clone()
                });
                ProcessInfo {
                    pid: p.pid().as_u32(),
                    parent_pid: p.parent().map(|pp| pp.as_u32()),
                    name: p.name().to_string_lossy().into_owned(),
                    exe: p.exe().map(|e| e.display().to_string()),
                    user,
                    cpu_percent: (p.cpu_usage() / cpus).clamp(0.0, 100.0),
                    memory_bytes: p.memory(),
                    started_at: p.start_time() as i64 * 1000,
                    arch: platform::arch(p.pid().as_u32()),
                }
            })
            .collect();
        out.sort_by_key(|p| p.pid);
        out
    }

    /// Terminates `pid` if it is still the process named in `req` and is not critical to Windows.
    pub fn kill(&self, pid: u32, req: &KillRequest) -> Result<(), String> {
        if pid == std::process::id() {
            return Err("refusing to terminate the Tervano Agent itself".into());
        }
        let mut sys = self.sys.lock().expect("not poisoned");
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
            true,
            ProcessRefreshKind::nothing(),
        );
        let p = sys
            .process(Pid::from_u32(pid))
            .ok_or_else(|| format!("process {pid} is no longer running"))?;
        let name = p.name().to_string_lossy();
        if !name.eq_ignore_ascii_case(&req.name) {
            return Err(format!(
                "process {pid} is now {name:?}, not {:?}; refresh and try again",
                req.name
            ));
        }
        if platform::is_critical(pid) {
            // Terminating a critical process bugchecks Windows; never do that remotely.
            return Err(format!(
                "{name} ({pid}) is a critical Windows process; terminating it would crash the computer"
            ));
        }
        if p.kill() {
            Ok(())
        } else {
            Err(format!(
                "Windows refused to terminate {name} ({pid}) (protected process or access denied)"
            ))
        }
    }
}

/// Account name (domain and user) for a SID string; `None` if it can't be resolved.
pub(crate) use platform::account_name;

#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
    use windows::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
        IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
    };
    use windows::Win32::System::Threading::{
        IsProcessCritical, IsWow64Process2, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::{HSTRING, PWSTR};

    /// Runs `f` with a query-only handle to `pid`, closing it afterwards.
    fn with_process<T>(pid: u32, f: impl FnOnce(HANDLE) -> Option<T>) -> Option<T> {
        // SAFETY: OpenProcess has no memory preconditions; the handle is closed exactly once below.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let r = f(h);
        // SAFETY: `h` is a valid handle we own.
        unsafe {
            let _ = CloseHandle(h);
        }
        r
    }

    pub fn arch(pid: u32) -> Option<String> {
        with_process(pid, |h| {
            let (mut process, mut native) =
                (IMAGE_FILE_MACHINE::default(), IMAGE_FILE_MACHINE::default());
            // SAFETY: valid handle; both out-params point to live locals.
            unsafe { IsWow64Process2(h, &mut process, Some(&mut native)) }.ok()?;
            // UNKNOWN means "not under WOW64", i.e. the process runs as the native architecture.
            let m = if process == IMAGE_FILE_MACHINE_UNKNOWN {
                native
            } else {
                process
            };
            Some(
                match m {
                    IMAGE_FILE_MACHINE_AMD64 => "x64",
                    IMAGE_FILE_MACHINE_I386 => "x86",
                    IMAGE_FILE_MACHINE_ARM64 => "arm64",
                    IMAGE_FILE_MACHINE_ARMNT => "arm",
                    _ => "other",
                }
                .to_owned(),
            )
        })
    }

    pub fn is_critical(pid: u32) -> bool {
        // Unopenable (e.g. protected) processes are treated as critical: refuse rather than guess.
        with_process(pid, |h| {
            let mut critical = Default::default();
            // SAFETY: valid handle; out-param points to a live local.
            unsafe { IsProcessCritical(h, &mut critical) }.ok()?;
            Some(critical.as_bool())
        })
        .unwrap_or(true)
    }

    /// `DOMAIN\user` for a SID string such as `S-1-5-21-…`.
    pub fn account_name(sid: &str) -> Option<String> {
        let mut psid = PSID::default();
        // SAFETY: on success the API LocalAlloc's `psid`, freed once at the end.
        unsafe { ConvertStringSidToSidW(&HSTRING::from(sid), &mut psid) }.ok()?;
        let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind = SID_NAME_USE::default();
        // SAFETY: buffers are valid for the lengths passed; `psid` is a valid SID.
        let ok = unsafe {
            LookupAccountSidW(
                None,
                psid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut kind,
            )
        }
        .is_ok();
        // SAFETY: `psid` came from ConvertStringSidToSidW and is not used after this.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psid.0)));
        }
        if !ok {
            return None;
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        Some(if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        })
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn arch(_pid: u32) -> Option<String> {
        None
    }
    pub fn is_critical(_pid: u32) -> bool {
        false
    }
    pub fn account_name(_sid: &str) -> Option<String> {
        None
    }
}
