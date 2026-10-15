//! Minimal safe wrapper over the Windows registry read APIs (shared by inventory modules).

use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, KEY_WRITE, REG_OPTION_NON_VOLATILE,
    REG_SAM_FLAGS, REG_VALUE_TYPE, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ,
    RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegDeleteTreeW, RegDeleteValueW,
    RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegSetValueExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

pub use windows::Win32::System::Registry::{
    HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_LOCAL_MACHINE, HKEY_USERS,
};

/// Human-readable text for a registry API error code.
pub fn error_text(code: WIN32_ERROR) -> String {
    windows::core::Error::from_hresult(code.to_hresult()).message()
}

fn check(code: WIN32_ERROR) -> Result<(), WIN32_ERROR> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(code)
    }
}

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

fn view_flags(view: View) -> REG_SAM_FLAGS {
    match view {
        View::Native => REG_SAM_FLAGS(0),
        View::Wow64_64 => KEY_WOW64_64KEY,
        View::Wow64_32 => KEY_WOW64_32KEY,
    }
}

impl Key {
    pub fn open(root: HKEY, path: &str, view: View) -> Option<Key> {
        Key::open_with(root, path, view, false).ok()
    }

    /// Opens for reading, or reading and writing; the error code says why it failed.
    pub fn open_with(root: HKEY, path: &str, view: View, write: bool) -> Result<Key, WIN32_ERROR> {
        let sam = KEY_READ | view_flags(view) | if write { KEY_WRITE } else { REG_SAM_FLAGS(0) };
        let mut h = HKEY::default();
        // SAFETY: the path is a valid wide string for the call; `h` is a live out-param.
        check(unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, sam, &mut h) })?;
        Ok(Key(h))
    }

    /// Opens for read/write, creating missing keys along the path.
    pub fn create(root: HKEY, path: &str, view: View) -> Result<Key, WIN32_ERROR> {
        let mut h = HKEY::default();
        // SAFETY: wide strings live for the call; `h` is a live out-param.
        check(unsafe {
            RegCreateKeyExW(
                root,
                &HSTRING::from(path),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | view_flags(view),
                None,
                &mut h,
                None,
            )
        })?;
        Ok(Key(h))
    }

    /// All values as (name, type, raw bytes).
    pub fn raw_values(&self) -> Vec<(String, u32, Vec<u8>)> {
        let (mut max_name, mut max_data) = (0u32, 0u32);
        // SAFETY: out-params are live locals; everything else is null.
        let rc = unsafe {
            RegQueryInfoKeyW(
                self.0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&mut max_name),
                Some(&mut max_data),
                None,
                None,
            )
        };
        if rc != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut name = vec![0u16; max_name as usize + 1];
        let mut data = vec![0u8; max_data as usize];
        let mut out = Vec::new();
        for i in 0.. {
            let mut name_len = name.len() as u32;
            let mut data_len = data.len() as u32;
            let mut ty = 0u32;
            // SAFETY: buffers are valid for the lengths passed.
            let rc = unsafe {
                RegEnumValueW(
                    self.0,
                    i,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut ty),
                    Some(data.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            if rc != ERROR_SUCCESS {
                break; // ERROR_NO_MORE_ITEMS, or a value grew since RegQueryInfoKey (rare)
            }
            out.push((
                String::from_utf16_lossy(&name[..name_len as usize]),
                ty,
                data[..data_len as usize].to_vec(),
            ));
        }
        out
    }

    pub fn set_raw(&self, name: &str, ty: u32, data: &[u8]) -> Result<(), WIN32_ERROR> {
        // SAFETY: `data` is a valid byte slice; the name is a valid wide string.
        check(unsafe {
            RegSetValueExW(
                self.0,
                &HSTRING::from(name),
                None,
                REG_VALUE_TYPE(ty),
                Some(data),
            )
        })
    }

    pub fn delete_value(&self, name: &str) -> Result<(), WIN32_ERROR> {
        // SAFETY: valid key handle and wide string.
        check(unsafe { RegDeleteValueW(self.0, &HSTRING::from(name)) })
    }

    /// Deletes `sub` and everything below it.
    pub fn delete_tree(&self, sub: &str) -> Result<(), WIN32_ERROR> {
        // SAFETY: valid key handle and wide string.
        check(unsafe { RegDeleteTreeW(self.0, &HSTRING::from(sub)) })
    }

    /// Deletes `sub`, which must have no subkeys.
    pub fn delete_leaf(&self, sub: &str, view: View) -> Result<(), WIN32_ERROR> {
        // SAFETY: valid key handle and wide string.
        check(unsafe { RegDeleteKeyExW(self.0, &HSTRING::from(sub), view_flags(view).0, None) })
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
