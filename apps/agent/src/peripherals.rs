//! Printers and mapped network drives (PLAN §19 parity rows "Printer management", "Drive mappings"; T-710).

use tervano_protocol::Peripherals;

#[cfg(windows)]
pub fn inventory() -> Result<Peripherals, String> {
    Ok(Peripherals {
        printers: printers()?,
        mapped_drives: mapped_drives(),
    })
}

#[cfg(not(windows))]
pub fn inventory() -> Result<Peripherals, String> {
    Err("printer and drive inventory is only implemented on Windows".into())
}

#[cfg(windows)]
fn printers() -> Result<Vec<tervano_protocol::PrinterInfo>, String> {
    use tervano_protocol::PrinterInfo;
    use windows::Win32::Graphics::Printing::{
        EnumPrintersW, PRINTER_ATTRIBUTE_NETWORK, PRINTER_ATTRIBUTE_SHARED,
        PRINTER_ATTRIBUTE_WORK_OFFLINE, PRINTER_ENUM_CONNECTIONS, PRINTER_ENUM_LOCAL,
        PRINTER_INFO_2W,
    };
    use windows::core::{PCWSTR, PWSTR};

    const STATUS: &[(u32, &str)] = &[
        (0x1, "paused"),
        (0x2, "error"),
        (0x4, "pending deletion"),
        (0x8, "paper jam"),
        (0x10, "paper out"),
        (0x80, "offline"),
        (0x200, "busy"),
        (0x400, "printing"),
        (0x1000, "not available"),
        (0x20000, "toner low"),
        (0x40000, "no toner"),
        (0x100000, "needs attention"),
        (0x400000, "door open"),
    ];
    let s = |p: PWSTR| -> Option<String> {
        // SAFETY: the pointer is either null or a NUL-terminated string inside the enum buffer.
        let v = unsafe { (!p.is_null()).then(|| p.to_string().ok()).flatten() }?;
        (!v.trim().is_empty()).then(|| v.trim().to_owned())
    };

    let flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
    let (mut needed, mut count) = (0u32, 0u32);
    // Size probe. SAFETY: no buffer; out-params are live locals.
    let _ = unsafe { EnumPrintersW(flags, PCWSTR::null(), 2, None, &mut needed, &mut count) };
    if needed == 0 {
        return Ok(Vec::new());
    }
    // u64 storage keeps the PRINTER_INFO_2W array aligned.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` holds `needed` bytes.
    unsafe {
        EnumPrintersW(
            flags,
            PCWSTR::null(),
            2,
            Some(std::slice::from_raw_parts_mut(
                buf.as_mut_ptr().cast::<u8>(),
                buf.len() * 8,
            )),
            &mut needed,
            &mut count,
        )
    }
    .map_err(|e| format!("listing printers failed: {e}"))?;
    // SAFETY: the API wrote `count` PRINTER_INFO_2W records at the start of the aligned buffer.
    let infos = unsafe {
        std::slice::from_raw_parts(buf.as_ptr().cast::<PRINTER_INFO_2W>(), count as usize)
    };
    let mut out: Vec<PrinterInfo> = infos
        .iter()
        .map(|p| {
            let mut status: Vec<String> = STATUS
                .iter()
                .filter(|(bit, _)| p.Status & bit != 0)
                .map(|(_, name)| (*name).to_owned())
                .collect();
            let offline =
                p.Status & 0x80 != 0 || p.Attributes & PRINTER_ATTRIBUTE_WORK_OFFLINE != 0;
            if offline && !status.iter().any(|s| s == "offline") {
                status.push("offline".into());
            }
            PrinterInfo {
                name: s(p.pPrinterName).unwrap_or_default(),
                driver: s(p.pDriverName),
                port: s(p.pPortName),
                share_name: s(p.pShareName),
                location: s(p.pLocation),
                shared: p.Attributes & PRINTER_ATTRIBUTE_SHARED != 0,
                network: p.Attributes & PRINTER_ATTRIBUTE_NETWORK != 0,
                offline,
                status,
                jobs: p.cJobs,
            }
        })
        .collect();
    out.sort_by_key(|p| p.name.to_lowercase());
    Ok(out)
}

#[cfg(windows)]
fn mapped_drives() -> Vec<tervano_protocol::DriveMapping> {
    use crate::reg::{HKEY_USERS, Key, View};
    use tervano_protocol::DriveMapping;
    let mut out = Vec::new();
    let Some(users) = Key::open(HKEY_USERS, "", View::Native) else {
        return out;
    };
    for sid in users.subkeys() {
        if !sid.starts_with("S-1-5-21-") || sid.ends_with("_Classes") {
            continue;
        }
        let Some(network) = users.sub(&format!(r"{sid}\Network")) else {
            continue;
        };
        let user = crate::processes::account_name(&sid).unwrap_or_else(|| sid.clone());
        for letter in network.subkeys() {
            let Some(k) = network.sub(&letter) else {
                continue;
            };
            if let Some(remote_path) = k.string("RemotePath") {
                out.push(DriveMapping {
                    user: user.clone(),
                    letter: format!("{}:", letter.to_uppercase()),
                    remote_path,
                    connect_as: k.string("UserName"),
                });
            }
        }
    }
    out.sort_by(|a, b| (&a.user, &a.letter).cmp(&(&b.user, &b.letter)));
    out
}
