//! Windows Event Log browsing (PLAN §7, T-702). Queries are filtered on the endpoint so only the
//! requested records cross the network — never a full log download.

use tervano_protocol::{EventQuery, EventRecord};

pub const DEFAULT_LIMIT: u32 = 100;
pub const MAX_LIMIT: u32 = 500;

/// Builds the XPath filter. Every interpolated value is validated first, so a request can't
/// inject XPath.
fn xpath(q: &EventQuery) -> Result<String, String> {
    let mut conds = Vec::new();
    if let Some(l) = q.max_level {
        if !(1..=5).contains(&l) {
            return Err("max_level must be 1-5".into());
        }
        // Level 0 ("log always") is informational in practice.
        conds.push(format!(
            "(Level<={l}{})",
            if l >= 4 { " or Level=0" } else { "" }
        ));
    }
    if let Some(p) = q.provider.as_deref().filter(|p| !p.is_empty()) {
        if p.len() > 256
            || !p
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " ._-/".contains(c))
        {
            return Err("provider may contain only letters, digits, space . _ - /".into());
        }
        conds.push(format!("Provider[@Name='{p}']"));
    }
    if let Some(id) = q.event_id {
        conds.push(format!("(EventID={id})"));
    }
    if let Some(m) = q.within_minutes {
        conds.push(format!(
            "TimeCreated[timediff(@SystemTime) <= {}]",
            u64::from(m) * 60_000
        ));
    }
    Ok(if conds.is_empty() {
        "*".into()
    } else {
        format!("*[System[{}]]", conds.join(" and "))
    })
}

fn validate_channel(c: &str) -> Result<(), String> {
    if c.is_empty() || c.len() > 512 || c.contains('\0') {
        return Err("invalid channel name".into());
    }
    Ok(())
}

#[cfg(windows)]
pub use platform::{channels, query};

#[cfg(windows)]
mod platform {
    use super::*;
    use std::collections::HashMap;
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
    use windows::Win32::System::EventLog::{
        EVT_HANDLE, EVT_VARIANT, EvtClose, EvtCreateRenderContext, EvtFormatMessage,
        EvtFormatMessageEvent, EvtNext, EvtNextChannelPath, EvtOpenChannelEnum,
        EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
        EvtRender, EvtRenderContextSystem, EvtRenderEventValues, EvtSystemEventID,
        EvtSystemEventRecordId, EvtSystemLevel, EvtSystemProviderName, EvtSystemTimeCreated,
    };
    use windows::core::{HSTRING, PCWSTR};

    /// EVT_HANDLE that closes itself.
    struct Evt(EVT_HANDLE);
    impl Drop for Evt {
        fn drop(&mut self) {
            // SAFETY: we own the handle and close it exactly once.
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }

    fn is(e: &windows::core::Error, code: windows::Win32::Foundation::WIN32_ERROR) -> bool {
        e.code() == code.to_hresult()
    }

    pub fn channels() -> Result<Vec<String>, String> {
        // SAFETY: no pointer arguments; closed by `Evt`.
        let en = Evt(unsafe { EvtOpenChannelEnum(None, 0) }.map_err(|e| e.to_string())?);
        let mut buf = vec![0u16; 512];
        let mut out = Vec::new();
        loop {
            let mut used = 0u32;
            // SAFETY: `buf` is valid for its length; `used` is a live local.
            match unsafe { EvtNextChannelPath(en.0, Some(&mut buf), &mut used) } {
                Ok(()) => out.push(String::from_utf16_lossy(
                    &buf[..(used as usize).saturating_sub(1)],
                )),
                Err(e) if is(&e, ERROR_NO_MORE_ITEMS) => break,
                Err(e) if is(&e, ERROR_INSUFFICIENT_BUFFER) => buf.resize(used as usize, 0),
                Err(e) => return Err(format!("listing channels failed: {e}")),
            }
        }
        out.sort_by_key(|c| c.to_lowercase());
        Ok(out)
    }

    pub fn query(q: &EventQuery) -> Result<Vec<EventRecord>, String> {
        validate_channel(&q.channel)?;
        let filter = xpath(q)?;
        let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
        // SAFETY: wide strings live for the call; the result set is closed by `Evt`.
        let rs = Evt(unsafe {
            EvtQuery(
                None,
                &HSTRING::from(q.channel.as_str()),
                &HSTRING::from(filter.as_str()),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )
        }
        .map_err(|e| format!("cannot query {}: {e}", q.channel))?);
        // SAFETY: no value paths; closed by `Evt`.
        let ctx = Evt(
            unsafe { EvtCreateRenderContext(None, EvtRenderContextSystem.0) }
                .map_err(|e| e.to_string())?,
        );
        let mut publishers: HashMap<String, Option<Evt>> = HashMap::new();
        let mut out = Vec::with_capacity(limit);
        let mut raw = [0isize; 32];
        while out.len() < limit {
            let mut got = 0u32;
            // SAFETY: `raw` is valid for 32 handles; each returned handle is wrapped in `Evt` below.
            match unsafe { EvtNext(rs.0, &mut raw, 5_000, 0, &mut got) } {
                Ok(()) => {}
                Err(e) if is(&e, ERROR_NO_MORE_ITEMS) => break,
                Err(e) => return Err(format!("reading {} failed: {e}", q.channel)),
            }
            let events: Vec<Evt> = raw[..got as usize]
                .iter()
                .map(|&h| Evt(EVT_HANDLE(h)))
                .collect();
            for ev in &events {
                if out.len() == limit {
                    break;
                }
                if let Some(r) = render(&ctx, ev, &mut publishers) {
                    out.push(r);
                }
            }
        }
        Ok(out)
    }

    /// FILETIME (100 ns since 1601) → Unix milliseconds.
    fn filetime_ms(ft: u64) -> i64 {
        (ft / 10_000) as i64 - 11_644_473_600_000
    }

    fn render(
        ctx: &Evt,
        ev: &Evt,
        publishers: &mut HashMap<String, Option<Evt>>,
    ) -> Option<EventRecord> {
        let (mut used, mut count) = (0u32, 0u32);
        // Probe for size. SAFETY: null buffer with size 0 is the documented way to size it.
        let _ = unsafe {
            EvtRender(
                Some(ctx.0),
                ev.0,
                EvtRenderEventValues.0,
                0,
                None,
                &mut used,
                &mut count,
            )
        };
        // u64 storage keeps EVT_VARIANTs aligned.
        let mut buf = vec![0u64; (used as usize).div_ceil(8)];
        // SAFETY: `buf` holds `used` bytes; out-params are live locals.
        unsafe {
            EvtRender(
                Some(ctx.0),
                ev.0,
                EvtRenderEventValues.0,
                used,
                Some(buf.as_mut_ptr().cast()),
                &mut used,
                &mut count,
            )
        }
        .ok()?;
        // SAFETY: the API wrote `count` EVT_VARIANTs at the start of `buf`.
        let vals: &[EVT_VARIANT] =
            unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), count as usize) };
        let get = |id: i32| vals.get(id as usize).filter(|v| v.Type != 0);
        // SAFETY: each union field read matches the documented type of that system property.
        let (provider, event_id, level, time, record_id) = unsafe {
            (
                get(EvtSystemProviderName.0)
                    .and_then(|v| v.Anonymous.StringVal.to_string().ok())
                    .unwrap_or_default(),
                get(EvtSystemEventID.0).map_or(0, |v| u32::from(v.Anonymous.UInt16Val)),
                get(EvtSystemLevel.0).map_or(0, |v| v.Anonymous.ByteVal),
                get(EvtSystemTimeCreated.0).map_or(0, |v| filetime_ms(v.Anonymous.FileTimeVal)),
                get(EvtSystemEventRecordId.0).map_or(0, |v| v.Anonymous.UInt64Val),
            )
        };
        let meta = publishers
            .entry(provider.clone())
            .or_insert_with(|| {
                // SAFETY: wide string lives for the call; closed by `Evt`.
                unsafe {
                    EvtOpenPublisherMetadata(
                        None,
                        &HSTRING::from(provider.as_str()),
                        PCWSTR::null(),
                        0,
                        0,
                    )
                }
                .ok()
                .map(Evt)
            })
            .as_ref()
            .map(|m| m.0);
        Some(EventRecord {
            record_id,
            time,
            level,
            event_id,
            message: message(meta, ev),
            provider,
        })
    }

    fn message(meta: Option<EVT_HANDLE>, ev: &Evt) -> Option<String> {
        let mut used = 0u32;
        // Size probe. SAFETY: no buffer with size 0.
        let _ = unsafe {
            EvtFormatMessage(
                meta,
                Some(ev.0),
                0,
                None,
                EvtFormatMessageEvent.0,
                None,
                &mut used,
            )
        };
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; used as usize];
        // SAFETY: `buf` is valid for `used` u16s.
        unsafe {
            EvtFormatMessage(
                meta,
                Some(ev.0),
                0,
                None,
                EvtFormatMessageEvent.0,
                Some(&mut buf),
                &mut used,
            )
        }
        .ok()?;
        let s = String::from_utf16_lossy(&buf[..(used as usize).saturating_sub(1)]);
        // Messages can be huge (e.g. dumps); the list view only needs the gist.
        Some(s.replace('\0', "").trim().chars().take(4000).collect())
    }
}

#[cfg(not(windows))]
mod unsupported {
    use super::*;
    const MSG: &str = "event logs are only implemented on Windows";
    pub fn channels() -> Result<Vec<String>, String> {
        Err(MSG.into())
    }
    pub fn query(q: &EventQuery) -> Result<Vec<EventRecord>, String> {
        validate_channel(&q.channel)?;
        xpath(q)?;
        Err(MSG.into())
    }
}
#[cfg(not(windows))]
pub use unsupported::{channels, query};
