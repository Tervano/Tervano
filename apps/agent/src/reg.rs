//! Minimal safe wrapper over the Windows registry read APIs (shared by inventory modules).

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_SAM_FLAGS, RRF_NOEXPAND,
    RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW,
    RegGetValueW, RegOpenKeyExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

pub use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, HKEY_USERS};

/// Which registry view to open on 64-bit Windows.
#[derive(Clone, Copy)]
pub enum View {
    Native,
    Wow64_64,
    Wow64_32,
}

/// An open registry key, closed on drop.
pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it exactly once.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

impl Key {
    pub fn open(root: HKEY, path: &str, view: View) -> Option<Key> {
        let sam = KEY_READ
            | match view {
                View::Native => REG_SAM_FLAGS(0),
                View::Wow64_64 => KEY_WOW64_64KEY,
                View::Wow64_32 => KEY_WOW64_32KEY,
            };
        let mut h = HKEY::default();
        // SAFETY: the path is a valid wide string for the call; `h` is a live out-param.
        let rc = unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, sam, &mut h) };
        (rc == ERROR_SUCCESS).then(|| Key(h))
    }

    /// Opens a subkey with the same access as this key's view.
    pub fn sub(&self, name: &str) -> Option<Key> {
        Key::open(self.0, name, View::Native)
    }

    pub fn subkeys(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = [0u16; 256]; // registry key names are at most 255 chars
        for i in 0.. {
            let mut len = buf.len() as u32;
            // SAFETY: `buf` is valid for `len` u16s; other optional params are null.
            let rc = unsafe {
                RegEnumKeyExW(
                    self.0,
                    i,
                    Some(PWSTR(buf.as_mut_ptr())),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if rc != ERROR_SUCCESS {
                break; // ERROR_NO_MORE_ITEMS (or a key vanished mid-walk)
            }
            out.push(String::from_utf16_lossy(&buf[..len as usize]));
        }
        out
    }

    /// REG_SZ or REG_EXPAND_SZ (unexpanded).
    pub fn string(&self, name: &str) -> Option<String> {
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
        let value = HSTRING::from(name);
        let mut size = 0u32;
        // Size probe. SAFETY: null data pointer with a size out-param is the documented probe.
        let rc = unsafe {
            RegGetValueW(
                self.0,
                PCWSTR::null(),
                &value,
                flags,
                None,
                None,
                Some(&mut size),
            )
        };
        if rc != ERROR_SUCCESS || size < 2 {
            return None;
        }
        let mut buf = vec![0u16; size as usize / 2];
        // SAFETY: `buf` holds `size` bytes.
        let rc = unsafe {
            RegGetValueW(
                self.0,
                PCWSTR::null(),
                &value,
                flags,
                None,
                Some(buf.as_mut_ptr().cast()),
                Some(&mut size),
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let chars = (size as usize / 2).saturating_sub(1).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..chars]).trim().to_owned();
        (!s.is_empty()).then_some(s)
    }

    pub fn dword(&self, name: &str) -> Option<u32> {
        let mut v = 0u32;
        let mut size = 4u32;
        // SAFETY: `v` is a valid 4-byte buffer and `size` says so.
        let rc = unsafe {
            RegGetValueW(
                self.0,
                PCWSTR::null(),
                &HSTRING::from(name),
                RRF_RT_REG_DWORD,
                None,
                Some((&mut v as *mut u32).cast()),
                Some(&mut size),
            )
        };
        (rc == ERROR_SUCCESS).then_some(v)
    }

    /// True if a value of any type exists under this name.
    pub fn has_value(&self, name: &str) -> bool {
        let mut size = 0u32;
        // SAFETY: size-only probe, no data buffer.
        let rc = unsafe {
            RegGetValueW(
                self.0,
                PCWSTR::null(),
                &HSTRING::from(name),
                windows::Win32::System::Registry::RRF_RT_ANY,
                None,
                None,
                Some(&mut size),
            )
        };
        rc == ERROR_SUCCESS
    }
}
