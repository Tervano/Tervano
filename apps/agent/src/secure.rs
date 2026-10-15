//! Protection for local identity material (PLAN §12.11).

/// Encrypts `data` for the current account (LocalSystem when running as the service).
#[cfg(windows)]
pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    dpapi(data, true)
}

#[cfg(windows)]
pub fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    dpapi(data, false)
}

#[cfg(windows)]
fn dpapi(data: &[u8], encrypt: bool) -> anyhow::Result<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` points at `data`, alive for the call and only read by the API. On success the API
    // allocates `out.pbData` with LocalAlloc; we copy it and free it exactly once.
    unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )?;
        } else {
            CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )?;
        }
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData.cast())));
        Ok(bytes)
    }
}

// shortcut: no OS key store on non-Windows yet; secret stays plaintext there until T-957.
#[cfg(not(windows))]
pub fn protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(not(windows))]
pub fn unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(data.to_vec())
}

/// Limits `dir` (and everything in it) to SYSTEM and Administrators. Service mode only:
/// running this as an ordinary user would lock that user out of their own dev state dir.
#[cfg(windows)]
pub fn restrict_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    // Full path so a planted icacls.exe on PATH can't run as SYSTEM.
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let icacls = std::path::Path::new(&root)
        .join("System32")
        .join("icacls.exe");
    let status = std::process::Command::new(icacls)
        .arg(dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/T",
            "/Q",
        ])
        .status()?;
    anyhow::ensure!(
        status.success(),
        "icacls failed on {} ({status})",
        dir.display()
    );
    Ok(())
}
