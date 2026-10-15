//! Hardware/firmware inventory (PLAN §7 "Hardware and health", T-703).
//! Collected on request only — never on the heartbeat path (PLAN §14).

use sysinfo::{DiskKind, Disks, System};
use tervano_protocol::{DiskInfo, HardwareInventory};

pub fn hardware() -> HardwareInventory {
    let mut sys = System::new();
    sys.refresh_memory();
    // CPU usage needs two samples.
    sys.refresh_cpu_all();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu_all();
    let smb = platform::smbios().unwrap_or_default();
    let disks = Disks::new_with_refreshed_list()
        .list()
        .iter()
        .map(|d| DiskInfo {
            mount_point: d.mount_point().display().to_string(),
            label: d.name().to_string_lossy().into_owned(),
            file_system: d.file_system().to_string_lossy().into_owned(),
            total_bytes: d.total_space(),
            free_bytes: d.available_space(),
            removable: d.is_removable(),
            kind: match d.kind() {
                DiskKind::SSD => "ssd",
                DiskKind::HDD => "hdd",
                _ => "unknown",
            }
            .into(),
        })
        .collect();
    HardwareInventory {
        manufacturer: smb.manufacturer,
        model: smb.model,
        serial_number: smb.serial,
        bios_vendor: smb.bios_vendor,
        bios_version: smb.bios_version,
        bios_date: smb.bios_date,
        cpu_model: sys
            .cpus()
            .first()
            .map(|c| c.brand().trim().to_owned())
            .unwrap_or_default(),
        cpu_physical_cores: System::physical_core_count().map(|n| n as u32),
        cpu_logical_cores: sys.cpus().len() as u32,
        cpu_usage_percent: sys.global_cpu_usage(),
        memory_total_bytes: sys.total_memory(),
        memory_used_bytes: sys.used_memory(),
        disks,
        boot_time: System::boot_time() as i64 * 1000,
        secure_boot: platform::secure_boot(),
        tpm_version: platform::tpm_version(),
        battery: platform::battery(),
    }
}

/// Fields read from the SMBIOS tables.
#[derive(Default)]
struct Smbios {
    manufacturer: Option<String>,
    model: Option<String>,
    serial: Option<String>,
    bios_vendor: Option<String>,
    bios_version: Option<String>,
    bios_date: Option<String>,
}

/// Parses raw SMBIOS structure data (the table after Windows' 8-byte RawSMBIOSData header).
/// Firmware data is untrusted input: every offset is bounds-checked and malformed tables just
/// yield fewer fields.
fn parse_smbios(mut table: &[u8]) -> Smbios {
    let mut out = Smbios::default();
    let mut board_serial = None;
    while table.len() >= 4 {
        let (kind, len) = (table[0], table[1] as usize);
        if len < 4 || len > table.len() {
            break;
        }
        let formatted = &table[..len];
        // Strings follow the formatted area, NUL-terminated, the set ending with an extra NUL.
        let rest = &table[len..];
        let Some(end) = rest.windows(2).position(|w| w == [0, 0]) else {
            break;
        };
        let strings: Vec<&[u8]> = rest[..end].split(|&b| b == 0).collect();
        // A string field holds a 1-based index into `strings`; 0 means "none".
        let s = |off: usize| -> Option<String> {
            let idx = *formatted.get(off)? as usize;
            let raw = strings.get(idx.checked_sub(1)?)?;
            let v = String::from_utf8_lossy(raw).trim().to_owned();
            // OEMs often leave placeholder text instead of a real value.
            let placeholder = v.is_empty()
                || [
                    "to be filled by o.e.m.",
                    "default string",
                    "system serial number",
                    "none",
                    "0",
                ]
                .contains(&v.to_lowercase().as_str());
            (!placeholder).then_some(v)
        };
        match kind {
            0 => {
                out.bios_vendor = s(4);
                out.bios_version = s(5);
                out.bios_date = s(8);
            }
            1 => {
                out.manufacturer = s(4);
                out.model = s(5);
                out.serial = s(7);
            }
            2 => board_serial = s(7),
            127 => break, // end-of-table
            _ => {}
        }
        table = &rest[end + 2..];
    }
    out.serial = out.serial.or(board_serial);
    out
}

#[cfg(windows)]
mod platform {
    use super::*;
    use tervano_protocol::BatteryInfo;
    use windows::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
    use windows::Win32::System::SystemInformation::{
        FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable,
    };
    use windows::Win32::System::TpmBaseServices::{TPM_DEVICE_INFO, Tbsi_GetDeviceInfo};
    use windows::core::HSTRING;

    pub fn smbios() -> Option<Smbios> {
        let rsmb = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"RSMB"));
        // SAFETY: a None buffer asks for the required size.
        let size = unsafe { GetSystemFirmwareTable(rsmb, 0, None) };
        if size < 8 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` is valid for `size` bytes.
        let got = unsafe { GetSystemFirmwareTable(rsmb, 0, Some(&mut buf)) } as usize;
        // RawSMBIOSData: 4 version bytes, u32 length, then the structure table.
        let len = u32::from_le_bytes(buf.get(4..8)?.try_into().ok()?) as usize;
        let table = buf.get(8..(8 + len).min(got))?;
        Some(parse_smbios(table))
    }

    pub fn secure_boot() -> Option<bool> {
        let mut v = 0u32;
        let mut size = 4u32;
        // SAFETY: `v` is a valid 4-byte buffer and `size` says so.
        unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                &HSTRING::from(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"),
                &HSTRING::from("UEFISecureBootEnabled"),
                RRF_RT_REG_DWORD,
                None,
                Some((&mut v as *mut u32).cast()),
                Some(&mut size),
            )
        }
        .is_ok()
        .then_some(v == 1)
    }

    pub fn tpm_version() -> Option<String> {
        let mut info = TPM_DEVICE_INFO::default();
        // SAFETY: `info` is a valid TPM_DEVICE_INFO and the size passed matches it.
        let rc = unsafe {
            Tbsi_GetDeviceInfo(
                size_of::<TPM_DEVICE_INFO>() as u32,
                (&mut info as *mut TPM_DEVICE_INFO).cast(),
            )
        };
        if rc != 0 {
            return None; // TBS_E_TPM_NOT_FOUND and friends
        }
        Some(match info.tpmVersion {
            1 => "1.2".into(),
            2 => "2.0".into(),
            v => format!("unknown ({v})"),
        })
    }

    pub fn battery() -> Option<BatteryInfo> {
        let mut st = SYSTEM_POWER_STATUS::default();
        // SAFETY: `st` is a valid out-param.
        unsafe { GetSystemPowerStatus(&mut st) }.ok()?;
        // BatteryFlag 128 = no system battery; 255 = unknown status.
        if st.BatteryFlag & 128 != 0 {
            return None;
        }
        Some(BatteryInfo {
            charge_percent: (st.BatteryLifePercent <= 100).then_some(st.BatteryLifePercent),
            on_ac_power: match st.ACLineStatus {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            },
        })
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn smbios() -> Option<Smbios> {
        None
    }
    pub fn secure_boot() -> Option<bool> {
        None
    }
    pub fn tpm_version() -> Option<String> {
        None
    }
    pub fn battery() -> Option<tervano_protocol::BatteryInfo> {
        None
    }
}
