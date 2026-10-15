//! Remote registry browsing and editing (PLAN §7 "Registry", T-706).

use tervano_protocol::{
    RegData, RegDeleteKeyRequest, RegDeleteValueRequest, RegKeyContents, RegKeyPath,
    RegSetValueRequest,
};

/// Normalizes a key path: no leading/trailing backslashes, no empty segments.
fn clean_path(p: &str) -> Result<String, String> {
    if p.len() > 2048 || p.contains('\0') {
        return Err("invalid registry path".into());
    }
    Ok(p.split('\\')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\\"))
}

fn decode(ty: u32, b: &[u8]) -> RegData {
    let utf16 = |b: &[u8]| -> Vec<u16> {
        b.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect()
    };
    let text = |b: &[u8]| {
        let w = utf16(b);
        let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        String::from_utf16_lossy(&w[..end])
    };
    match (ty, b.len()) {
        (1, _) => RegData::String(text(b)),
        (2, _) => RegData::ExpandString(text(b)),
        (7, _) => RegData::MultiString(
            String::from_utf16_lossy(&utf16(b))
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        ),
        (4, 4) => RegData::Dword(u32::from_le_bytes(b.try_into().expect("len 4"))),
        (11, 8) => RegData::Qword(u64::from_le_bytes(b.try_into().expect("len 8"))),
        (3, _) => RegData::Binary(hex::encode(b)),
        (0, 0) => RegData::None,
        _ => RegData::Other {
            type_id: ty,
            hex: hex::encode(b),
        },
    }
}

fn encode(d: &RegData) -> Result<(u32, Vec<u8>), String> {
    let wide = |s: &str| -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    let unhex = |h: &str| hex::decode(h).map_err(|e| format!("invalid hex data: {e}"));
    Ok(match d {
        RegData::String(s) => (1, wide(s)),
        RegData::ExpandString(s) => (2, wide(s)),
        RegData::MultiString(v) => {
            if v.iter().any(|s| s.is_empty() || s.contains('\0')) {
                return Err("multi-string entries must be non-empty and contain no NUL".into());
            }
            let mut b: Vec<u8> = v.iter().flat_map(|s| wide(s)).collect();
            b.extend([0, 0]);
            (7, b)
        }
        RegData::Dword(v) => (4, v.to_le_bytes().to_vec()),
        RegData::Qword(v) => (11, v.to_le_bytes().to_vec()),
        RegData::Binary(h) => (3, unhex(h)?),
        RegData::None => (0, Vec::new()),
        RegData::Other { type_id, hex } => (*type_id, unhex(hex)?),
    })
}

#[cfg(windows)]
pub use platform::{delete_key, delete_value, export, read, set_value};

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::reg::{self, Key, View};
    use tervano_protocol::{RegHive, RegValue, RegView};
    use windows::Win32::System::Registry::HKEY;

    fn root(h: RegHive) -> HKEY {
        match h {
            RegHive::LocalMachine => reg::HKEY_LOCAL_MACHINE,
            RegHive::Users => reg::HKEY_USERS,
            RegHive::ClassesRoot => reg::HKEY_CLASSES_ROOT,
            RegHive::CurrentConfig => reg::HKEY_CURRENT_CONFIG,
        }
    }

    fn hive_name(h: RegHive) -> &'static str {
        match h {
            RegHive::LocalMachine => "HKEY_LOCAL_MACHINE",
            RegHive::Users => "HKEY_USERS",
            RegHive::ClassesRoot => "HKEY_CLASSES_ROOT",
            RegHive::CurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }

    fn view(v: RegView) -> View {
        match v {
            RegView::Bits64 => View::Wow64_64,
            RegView::Bits32 => View::Wow64_32,
        }
    }

    fn describe(k: &RegKeyPath, path: &str) -> String {
        format!("{}\\{path}", hive_name(k.hive))
    }

    fn open(k: &RegKeyPath, write: bool) -> Result<(Key, String), String> {
        let path = clean_path(&k.path)?;
        let key = Key::open_with(root(k.hive), &path, view(k.view), write)
            .map_err(|e| format!("cannot open {}: {}", describe(k, &path), reg::error_text(e)))?;
        Ok((key, path))
    }

    pub fn read(k: &RegKeyPath) -> Result<RegKeyContents, String> {
        let (key, _) = open(k, false)?;
        let mut subkeys = key.subkeys();
        subkeys.sort_by_key(|s| s.to_lowercase());
        let mut values: Vec<RegValue> = key
            .raw_values()
            .into_iter()
            .map(|(name, ty, data)| RegValue {
                name,
                data: decode(ty, &data),
            })
            .collect();
        values.sort_by_key(|v| v.name.to_lowercase());
        Ok(RegKeyContents { subkeys, values })
    }

    pub fn set_value(req: &RegSetValueRequest) -> Result<(), String> {
        let path = clean_path(&req.key.path)?;
        let (ty, bytes) = encode(&req.data)?;
        let key = Key::create(root(req.key.hive), &path, view(req.key.view)).map_err(|e| {
            format!(
                "cannot open {} for writing: {}",
                describe(&req.key, &path),
                reg::error_text(e)
            )
        })?;
        key.set_raw(&req.name, ty, &bytes)
            .map_err(|e| format!("setting {:?} failed: {}", req.name, reg::error_text(e)))
    }

    pub fn delete_value(req: &RegDeleteValueRequest) -> Result<(), String> {
        let (key, _) = open(&req.key, true)?;
        key.delete_value(&req.name)
            .map_err(|e| format!("deleting {:?} failed: {}", req.name, reg::error_text(e)))
    }

    pub fn delete_key(req: &RegDeleteKeyRequest) -> Result<(), String> {
        let path = clean_path(&req.key.path)?;
        // Top-level keys such as HKLM\SOFTWARE or HKU\<SID> hold the system together; never
        // delete anything shallower than two levels.
        let Some((parent, child)) = path.rsplit_once('\\') else {
            return Err(format!(
                "refusing to delete top-level key {}",
                describe(&req.key, &path)
            ));
        };
        let parent_key = Key::open_with(root(req.key.hive), parent, view(req.key.view), true)
            .map_err(|e| {
                format!(
                    "cannot open {}: {}",
                    describe(&req.key, parent),
                    reg::error_text(e)
                )
            })?;
        let r = if req.recursive {
            parent_key.delete_tree(child)
        } else {
            parent_key.delete_leaf(child, view(req.key.view))
        };
        r.map_err(|e| {
            let has_subkeys = !req.recursive
                && Key::open(root(req.key.hive), &path, view(req.key.view))
                    .is_some_and(|k| !k.subkeys().is_empty());
            if has_subkeys {
                format!(
                    "{} has subkeys; confirm a recursive delete",
                    describe(&req.key, &path)
                )
            } else {
                format!(
                    "deleting {} failed: {}",
                    describe(&req.key, &path),
                    reg::error_text(e)
                )
            }
        })
    }

    const MAX_EXPORT_KEYS: usize = 20_000;
    const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;

    /// Exports the key and everything below it in regedit's `.reg` format.
    pub fn export(k: &RegKeyPath) -> Result<String, String> {
        let (key, path) = open(k, false)?;
        let mut out = String::from("Windows Registry Editor Version 5.00\r\n");
        let mut keys = 0usize;
        walk(
            &key,
            describe(k, &path).trim_end_matches('\\'),
            &mut out,
            &mut keys,
        )?;
        Ok(out)
    }

    fn walk(key: &Key, name: &str, out: &mut String, keys: &mut usize) -> Result<(), String> {
        *keys += 1;
        if *keys > MAX_EXPORT_KEYS || out.len() > MAX_EXPORT_BYTES {
            return Err(format!(
                "export too large (over {MAX_EXPORT_KEYS} keys or {} MB); export a smaller key",
                MAX_EXPORT_BYTES / 1024 / 1024
            ));
        }
        out.push_str(&format!("\r\n[{name}]\r\n"));
        for (vname, ty, data) in key.raw_values() {
            let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
            let lhs = if vname.is_empty() {
                "@".to_owned()
            } else {
                format!("\"{}\"", esc(&vname))
            };
            let bytes_hex = |b: &[u8]| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let rhs = match decode(ty, &data) {
                // REG_SZ is plain text unless it contains characters .reg can't express.
                RegData::String(s) if !s.contains(['\r', '\n']) => format!("\"{}\"", esc(&s)),
                RegData::Dword(v) => format!("dword:{v:08x}"),
                _ if ty == 3 => format!("hex:{}", bytes_hex(&data)),
                _ => format!("hex({ty:x}):{}", bytes_hex(&data)),
            };
            out.push_str(&format!("{lhs}={rhs}\r\n"));
        }
        for sub in key.subkeys() {
            // Subkeys we may not read are skipped rather than failing the whole export.
            if let Some(child) = key.sub(&sub) {
                walk(&child, &format!("{name}\\{sub}"), out, keys)?;
            }
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod unsupported {
    use super::*;
    const MSG: &str = "registry access is only available on Windows";
    pub fn read(k: &RegKeyPath) -> Result<RegKeyContents, String> {
        clean_path(&k.path)?;
        Err(MSG.into())
    }
    pub fn set_value(r: &RegSetValueRequest) -> Result<(), String> {
        encode(&r.data)?;
        Err(MSG.into())
    }
    pub fn delete_value(_: &RegDeleteValueRequest) -> Result<(), String> {
        Err(MSG.into())
    }
    pub fn delete_key(_: &RegDeleteKeyRequest) -> Result<(), String> {
        Err(MSG.into())
    }
    pub fn export(_: &RegKeyPath) -> Result<String, String> {
        let _ = decode(0, &[]);
        Err(MSG.into())
    }
}
#[cfg(not(windows))]
pub use unsupported::{delete_key, delete_value, export, read, set_value};
