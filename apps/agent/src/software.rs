//! Installed-software inventory and pending-reboot detection (PLAN §7 "Software", T-704).

use tervano_protocol::SoftwareInventory;

#[cfg(windows)]
pub fn inventory() -> SoftwareInventory {
    use crate::reg::{HKEY_LOCAL_MACHINE, HKEY_USERS, Key, View};
    use tervano_protocol::InstalledApp;

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    fn collect(root: &Key, scope: &str, out: &mut Vec<InstalledApp>) {
        for key in root.subkeys() {
            let Some(k) = root.sub(&key) else { continue };
            let Some(name) = k.string("DisplayName") else {
                continue;
            };
            // Same filters as Settings → Apps: hide OS components and patches of other entries.
            if k.dword("SystemComponent") == Some(1) || k.string("ParentKeyName").is_some() {
                continue;
            }
            out.push(InstalledApp {
                name,
                version: k.string("DisplayVersion"),
                publisher: k.string("Publisher"),
                install_date: k.string("InstallDate"),
                size_bytes: k.dword("EstimatedSize").map(|kb| u64::from(kb) * 1024),
                scope: scope.to_owned(),
                msi: k.dword("WindowsInstaller") == Some(1),
                has_uninstaller: k.string("UninstallString").is_some()
                    || k.string("QuietUninstallString").is_some(),
                uninstall_key: key,
            });
        }
    }

    let mut apps = Vec::new();
    for (view, scope) in [
        (View::Wow64_64, "machine-x64"),
        (View::Wow64_32, "machine-x86"),
    ] {
        if let Some(root) = Key::open(HKEY_LOCAL_MACHINE, UNINSTALL, view) {
            collect(&root, scope, &mut apps);
        }
    }
    // Per-user installs, for profiles whose hive is loaded (signed-in or service users).
    if let Some(users) = Key::open(HKEY_USERS, "", View::Native) {
        for sid in users.subkeys() {
            if !sid.starts_with("S-1-5-21-") || sid.ends_with("_Classes") {
                continue;
            }
            if let Some(root) = users.sub(&format!(r"{sid}\{UNINSTALL}")) {
                let who = crate::processes::account_name(&sid).unwrap_or(sid);
                collect(&root, &format!("user:{who}"), &mut apps);
            }
        }
    }
    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    // The same product can appear in more than one view; keep one row per name/version/scope.
    apps.dedup_by(|a, b| a.name == b.name && a.version == b.version && a.scope == b.scope);

    let mut reboot_pending = Vec::new();
    let key_exists = |path: &str| Key::open(HKEY_LOCAL_MACHINE, path, View::Wow64_64).is_some();
    if key_exists(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    ) {
        reboot_pending.push("Windows component servicing".into());
    }
    if key_exists(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    ) {
        reboot_pending.push("Windows Update".into());
    }
    if Key::open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        View::Native,
    )
    .is_some_and(|k| k.has_value("PendingFileRenameOperations"))
    {
        reboot_pending.push("pending file rename operations (installer or update)".into());
    }
    let name_at = |path: &str| {
        Key::open(HKEY_LOCAL_MACHINE, path, View::Native).and_then(|k| k.string("ComputerName"))
    };
    let (active, pending) = (
        name_at(r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"),
        name_at(r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"),
    );
    if active.is_some() && pending.is_some() && active != pending {
        reboot_pending.push("computer rename".into());
    }

    SoftwareInventory {
        apps,
        reboot_pending,
    }
}

#[cfg(not(windows))]
pub fn inventory() -> SoftwareInventory {
    // shortcut: no package-manager inventory on non-Windows yet (T-957).
    SoftwareInventory {
        apps: Vec::new(),
        reboot_pending: Vec::new(),
    }
}
