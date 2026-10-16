//! Technician token storage in Windows Credential Manager (T-306), so it never sits in plaintext
//! in console.toml. Stored per user (CRED_PERSIST_LOCAL_MACHINE: this user, this computer only).

#[cfg(windows)]
// No spaces or slashes, so `cmdkey /list:TervanoConsole-technician-token` can show or delete it.
const TARGET: &str = "TervanoConsole-technician-token";

#[cfg(windows)]
pub fn load_token() -> Option<String> {
    use windows::Win32::Security::Credentials::{
        CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
    };
    use windows::core::HSTRING;
    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: on success the API allocates `cred`, which we read once and free with CredFree.
    unsafe {
        CredReadW(&HSTRING::from(TARGET), CRED_TYPE_GENERIC, None, &mut cred).ok()?;
        let c = &*cred;
        let blob =
            std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec();
        CredFree(cred.cast());
        String::from_utf8(blob).ok().filter(|t| !t.is_empty())
    }
}

/// Stores `token`, or removes the credential when it is empty.
#[cfg(windows)]
pub fn save_token(token: &str) -> Result<(), String> {
    use windows::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredWriteW,
    };
    use windows::core::{HSTRING, PWSTR};
    if token.is_empty() {
        // SAFETY: plain call with a valid wide string; a missing credential is fine.
        let _ = unsafe { CredDeleteW(&HSTRING::from(TARGET), CRED_TYPE_GENERIC, None) };
        return Ok(());
    }
    let mut target: Vec<u16> = TARGET.encode_utf16().chain(std::iter::once(0)).collect();
    let mut user: Vec<u16> = "technician"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut blob = token.as_bytes().to_vec();
    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_mut_ptr()),
        UserName: PWSTR(user.as_mut_ptr()),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    // SAFETY: every pointer in `cred` points into a live local buffer for the duration of the call.
    unsafe { CredWriteW(&cred, 0) }
        .map_err(|e| format!("cannot store the token in Credential Manager: {e}"))
}

// shortcut: non-Windows consoles keep the token in console.toml (see Settings) until a keyring
// backend exists (T-957).
#[cfg(not(windows))]
pub fn load_token() -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn save_token(_token: &str) -> Result<(), String> {
    Ok(())
}
