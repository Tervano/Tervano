//! Read-only WMI/CIM queries (T-726) and patch status (T-711).

use tervano_protocol::{UpdateStatus, WmiQuery, WmiTable};

const MAX_ROWS: usize = 2000;

/// Only WQL that reads: SELECT and the association queries. Method calls are not reachable through
/// the query API at all; this check just gives a clear error instead of a WMI one.
fn validate(q: &WmiQuery) -> Result<String, String> {
    let ns = q.namespace.as_deref().unwrap_or(r"ROOT\CIMV2").trim();
    if ns.is_empty()
        || ns.len() > 256
        || !ns
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '\\')
    {
        return Err("namespace may contain only letters, digits, _ and \\".into());
    }
    let wql = q.wql.trim();
    let head = wql
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    if wql.len() > 4096 || !["SELECT", "ASSOCIATORS", "REFERENCES"].contains(&head.as_str()) {
        return Err("only read-only WQL is allowed (SELECT, ASSOCIATORS OF, REFERENCES OF)".into());
    }
    Ok(ns.to_owned())
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::collections::HashMap;
    use tervano_protocol::Hotfix;
    use wmi::{Variant, WMIConnection};

    fn text(v: &Variant) -> String {
        match v {
            Variant::Empty | Variant::Null => String::new(),
            Variant::String(s) => s.clone(),
            Variant::I1(n) => n.to_string(),
            Variant::I2(n) => n.to_string(),
            Variant::I4(n) => n.to_string(),
            Variant::I8(n) => n.to_string(),
            Variant::UI1(n) => n.to_string(),
            Variant::UI2(n) => n.to_string(),
            Variant::UI4(n) => n.to_string(),
            Variant::UI8(n) => n.to_string(),
            Variant::R4(n) => n.to_string(),
            Variant::R8(n) => n.to_string(),
            Variant::Bool(b) => b.to_string(),
            Variant::Array(a) => a.iter().map(text).collect::<Vec<_>>().join(", "),
            Variant::Unknown(_) | Variant::Object(_) => "(object)".into(),
        }
    }

    fn rows(ns: &str, wql: &str) -> Result<Vec<HashMap<String, Variant>>, String> {
        let con = WMIConnection::with_namespace_path(ns)
            .map_err(|e| format!("cannot open WMI namespace {ns}: {e}"))?;
        con.raw_query(wql).map_err(|e| {
            let e = e.to_string();
            // Common WBEM_E_* codes, which the crate reports only as hex.
            let hint = [
                (
                    "80041017",
                    "invalid query (check the WQL syntax and property names)",
                ),
                ("80041010", "no such class in this namespace"),
                ("8004100e", "no such namespace"),
                ("80041003", "access denied"),
                ("80041002", "not found"),
            ]
            .iter()
            .find(|(code, _)| e.to_ascii_lowercase().contains(code))
            .map(|(_, h)| format!(": {h}"))
            .unwrap_or_default();
            format!("WMI query failed{hint} ({e})")
        })
    }

    pub fn query(q: &WmiQuery) -> Result<WmiTable, String> {
        let ns = validate(q)?;
        let mut all = rows(&ns, q.wql.trim())?;
        let truncated = all.len() > MAX_ROWS;
        all.truncate(MAX_ROWS);
        // Column order: first-seen, but WMI system properties (__CLASS…) last.
        let mut columns: Vec<String> = Vec::new();
        for r in &all {
            let mut keys: Vec<&String> = r.keys().collect();
            keys.sort_by_key(|k| (k.starts_with("__"), k.to_lowercase()));
            for k in keys {
                if !columns.contains(k) {
                    columns.push(k.clone());
                }
            }
        }
        let rows = all
            .iter()
            .map(|r| {
                columns
                    .iter()
                    .map(|c| r.get(c).map(text).unwrap_or_default())
                    .collect()
            })
            .collect();
        Ok(WmiTable {
            columns,
            rows,
            truncated,
        })
    }

    pub fn classes(namespace: Option<&str>) -> Result<Vec<String>, String> {
        let q = WmiQuery {
            namespace: namespace.map(str::to_owned),
            // meta_class only accepts SELECT *.
            wql: "SELECT * FROM meta_class".into(),
        };
        let ns = validate(&q)?;
        let con = WMIConnection::with_namespace_path(&ns)
            .map_err(|e| format!("cannot open WMI namespace {ns}: {e}"))?;
        // The map deserializer drops system properties, so read each class object's name directly.
        let mut out: Vec<String> = con
            .exec_query(&q.wql)
            .map_err(|e| format!("listing classes failed: {e}"))?
            .filter_map(|o| o.ok()?.class().ok())
            // System classes (__Namespace, __Provider, …) are noise for technicians.
            .filter(|c| !c.starts_with("__"))
            .collect();
        out.sort_by_key(|c| c.to_lowercase());
        Ok(out)
    }

    pub fn updates() -> Result<UpdateStatus, String> {
        let s = |r: &HashMap<String, Variant>, k: &str| {
            r.get(k).map(text).filter(|v| !v.trim().is_empty())
        };
        let mut hotfixes: Vec<Hotfix> = rows(
            r"ROOT\CIMV2",
            "SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering",
        )?
        .iter()
        .filter_map(|r| {
            Some(Hotfix {
                id: s(r, "HotFixID")?,
                description: s(r, "Description"),
                installed_on: s(r, "InstalledOn"),
                installed_by: s(r, "InstalledBy"),
            })
        })
        .collect();
        // Newest first: InstalledOn is M/D/YYYY, so sort on a parsed key.
        let key = |h: &Hotfix| {
            h.installed_on
                .as_deref()
                .and_then(|d| {
                    let p: Vec<u32> = d.split('/').filter_map(|x| x.parse().ok()).collect();
                    (p.len() == 3).then(|| (p[2], p[0], p[1]))
                })
                .unwrap_or_default()
        };
        hotfixes.sort_by_key(|h| std::cmp::Reverse(key(h)));
        Ok(UpdateStatus {
            hotfixes,
            reboot_pending: crate::software::reboot_pending(),
        })
    }
}

#[cfg(windows)]
pub use platform::{classes, query, updates};

#[cfg(not(windows))]
pub fn query(q: &WmiQuery) -> Result<WmiTable, String> {
    validate(q)?;
    let _ = MAX_ROWS;
    Err("WMI is only available on Windows".into())
}
#[cfg(not(windows))]
pub fn classes(_: Option<&str>) -> Result<Vec<String>, String> {
    Err("WMI is only available on Windows".into())
}
#[cfg(not(windows))]
pub fn updates() -> Result<UpdateStatus, String> {
    Err("update status is only available on Windows".into())
}
