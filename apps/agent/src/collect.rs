//! Local state collection. Windows uses native APIs; other targets get a minimal std-only fallback
//! so the workspace builds everywhere (real non-Windows agents are T-957).

use tervano_protocol::{DeviceState, NetAddress};

pub fn device_state() -> DeviceState {
    let (hostname, domain) = platform::names();
    DeviceState {
        hostname,
        domain,
        os: platform::os(),
        addresses: addresses(),
        sessions: platform::sessions(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
    }
}

fn addresses() -> Vec<NetAddress> {
    let mut out: Vec<NetAddress> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| NetAddress {
            address: i.ip().to_string(),
            interface: i.name,
        })
        .collect();
    // Stable order so unchanged state compares equal.
    out.sort_by(|a, b| (&a.interface, &a.address).cmp(&(&b.interface, &b.address)));
    out
}

#[cfg(windows)]
mod platform {
    use tervano_protocol::{OsInfo, SessionState, UserSession};
    use windows::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
    };
    use windows::Win32::System::RemoteDesktop::*;
    use windows::Win32::System::SystemInformation::{
        COMPUTER_NAME_FORMAT, ComputerNameDnsDomain, ComputerNameDnsHostname, GetComputerNameExW,
    };
    use windows::core::{HSTRING, PWSTR};

    fn computer_name(kind: COMPUTER_NAME_FORMAT) -> String {
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        // SAFETY: buf is valid for `len` u16s; the API writes at most `len` and updates it.
        match unsafe { GetComputerNameExW(kind, Some(PWSTR(buf.as_mut_ptr())), &mut len) } {
            Ok(()) => String::from_utf16_lossy(&buf[..len as usize]),
            Err(_) => String::new(),
        }
    }

    pub fn names() -> (String, Option<String>) {
        let domain = computer_name(ComputerNameDnsDomain);
        (
            computer_name(ComputerNameDnsHostname),
            (!domain.is_empty()).then_some(domain),
        )
    }

    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    fn reg_string(value: &str) -> Option<String> {
        let mut buf = [0u16; 512];
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: buf is valid for `size` bytes; RRF_RT_REG_SZ guarantees a NUL-terminated string.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                &HSTRING::from(CURRENT_VERSION),
                &HSTRING::from(value),
                RRF_RT_REG_SZ,
                None,
                Some(buf.as_mut_ptr().cast()),
                Some(&mut size),
            )
        };
        rc.is_ok().then(|| {
            let chars = (size as usize / 2).saturating_sub(1);
            String::from_utf16_lossy(&buf[..chars])
        })
    }

    fn reg_dword(value: &str) -> Option<u32> {
        let mut v = 0u32;
        let mut size = 4u32;
        // SAFETY: v is a valid 4-byte buffer and size says so.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                &HSTRING::from(CURRENT_VERSION),
                &HSTRING::from(value),
                RRF_RT_REG_DWORD,
                None,
                Some((&mut v as *mut u32).cast()),
                Some(&mut size),
            )
        };
        rc.is_ok().then_some(v)
    }

    pub fn os() -> OsInfo {
        let build = reg_string("CurrentBuildNumber").unwrap_or_default();
        let mut name = reg_string("ProductName").unwrap_or_else(|| "Windows".into());
        // ProductName still says "Windows 10" on Windows 11; build 22000 is the documented cut-over.
        if build.parse::<u32>().is_ok_and(|b| b >= 22000) && !name.contains("Server") {
            name = name.replace("Windows 10", "Windows 11");
        }
        let ubr = reg_dword("UBR")
            .map(|u| format!(".{u}"))
            .unwrap_or_default();
        OsInfo {
            name,
            version: reg_string("DisplayVersion").unwrap_or_default(),
            build: format!("{build}{ubr}"),
        }
    }

    /// Reads a WTS string attribute of a session.
    fn session_string(id: u32, class: WTS_INFO_CLASS) -> String {
        let mut buf = PWSTR::null();
        let mut bytes = 0u32;
        // SAFETY: on success WTS allocates `buf`, which we read once and free with WTSFreeMemory.
        unsafe {
            if WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                id,
                class,
                &mut buf,
                &mut bytes,
            )
            .is_err()
                || buf.is_null()
            {
                return String::new();
            }
            let s = buf.to_string().unwrap_or_default();
            WTSFreeMemory(buf.0.cast());
            s
        }
    }

    /// Interactive sessions that have a user. Lock state is not available from this API (T-211).
    pub fn sessions() -> Vec<UserSession> {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: on success WTS allocates `count` WTS_SESSION_INFOW entries at `info`; freed below.
        let list = unsafe {
            if WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count)
                .is_err()
            {
                return Vec::new();
            }
            std::slice::from_raw_parts(info, count as usize)
        };
        let mut out: Vec<UserSession> = list
            .iter()
            .filter_map(|s| {
                let username = session_string(s.SessionId, WTSUserName);
                if username.is_empty() {
                    return None;
                }
                Some(UserSession {
                    session_id: s.SessionId,
                    username,
                    domain: session_string(s.SessionId, WTSDomainName),
                    state: match s.State {
                        s if s == WTSActive => SessionState::Active,
                        s if s == WTSDisconnected => SessionState::Disconnected,
                        _ => SessionState::Other,
                    },
                    // SAFETY: pWinStationName points into the WTS allocation, still alive here.
                    station: unsafe { s.pWinStationName.to_string() }.unwrap_or_default(),
                })
            })
            .collect();
        // SAFETY: `info` came from WTSEnumerateSessionsW and `list` is not used after this.
        unsafe { WTSFreeMemory(info.cast()) };
        out.sort_by_key(|s| s.session_id);
        out
    }
}

#[cfg(not(windows))]
mod platform {
    use tervano_protocol::{OsInfo, UserSession};

    pub fn names() -> (String, Option<String>) {
        let h = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
        (h.trim().to_owned(), None)
    }

    pub fn os() -> OsInfo {
        OsInfo {
            name: std::env::consts::OS.into(),
            version: String::new(),
            build: String::new(),
        }
    }

    pub fn sessions() -> Vec<UserSession> {
        Vec::new()
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn collects_real_state() {
        let s = super::device_state();
        assert!(!s.hostname.is_empty());
        assert!(s.os.name.starts_with("Windows"), "{:?}", s.os);
        assert!(!s.os.build.is_empty());
    }
}
