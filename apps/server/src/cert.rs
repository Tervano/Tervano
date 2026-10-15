//! `tervano-server cert init`: a private CA plus a server certificate, for sites without their own PKI.
//! Organizations with an enterprise CA should issue the server certificate from it instead.

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::path::Path;

fn year_now() -> i32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    1970 + (secs / 31_556_952) as i32
}

/// Fixed CA parameters: re-creating them with the stored key yields the same issuer,
/// so new server certs chain to the CA agents already trust.
fn ca_params() -> anyhow::Result<CertificateParams> {
    let y = year_now();
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name
        .push(DnType::CommonName, "Tervano Private CA");
    p.distinguished_name
        .push(DnType::OrganizationName, "Tervano");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // Year granularity is enough; Jan 1 of last year avoids "not yet valid" on skewed clocks.
    p.not_before = rcgen::date_time_ymd(y - 1, 1, 1);
    p.not_after = rcgen::date_time_ymd(y + 20, 1, 1);
    Ok(p)
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
    // shortcut: relies on the directory's ACLs; the server runbook says to restrict it (T-952).
}

/// Loads the CA from `out`, creating `ca.pem` + `ca-key.pem` on first use. Returns (key, ca.pem text).
fn load_or_create_ca(out: &Path) -> anyhow::Result<(KeyPair, String)> {
    std::fs::create_dir_all(out)?;
    let (ca_cert_path, ca_key_path) = (out.join("ca.pem"), out.join("ca-key.pem"));
    let ca_key = if ca_key_path.exists() {
        KeyPair::from_pem(&std::fs::read_to_string(&ca_key_path)?)
            .context("ca-key.pem is not a valid key")?
    } else {
        let key = KeyPair::generate()?;
        let ca_cert = ca_params()?.self_signed(&key)?;
        std::fs::write(&ca_cert_path, ca_cert.pem())?;
        write_private(&ca_key_path, &key.serialize_pem())?;
        println!(
            "created CA: {} (distribute to agents/consoles)",
            ca_cert_path.display()
        );
        key
    };
    let ca_pem =
        std::fs::read_to_string(&ca_cert_path).context("ca.pem missing next to ca-key.pem")?;
    Ok((ca_key, ca_pem))
}

/// Issues a leaf certificate from the CA in `out`, writing `<stem>.pem` (leaf + CA) and `<stem>-key.pem`.
fn issue(out: &Path, stem: &str, mut p: CertificateParams, years: i32) -> anyhow::Result<()> {
    let (ca_key, ca_pem) = load_or_create_ca(out)?;
    let issuer = Issuer::new(ca_params()?, &ca_key);
    let y = year_now();
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    p.not_before = rcgen::date_time_ymd(y - 1, 1, 1);
    p.not_after = rcgen::date_time_ymd(y + years, 1, 1);
    let key = KeyPair::generate()?;
    let cert = p.signed_by(&key, &issuer)?;
    let (cert_path, key_path) = (
        out.join(format!("{stem}.pem")),
        out.join(format!("{stem}-key.pem")),
    );
    std::fs::write(&cert_path, format!("{}{}", cert.pem(), ca_pem))?;
    write_private(&key_path, &key.serialize_pem())?;
    println!("wrote {} and {}", cert_path.display(), key_path.display());
    println!(
        "keep ca-key.pem offline-safe: anyone holding it can mint server and technician certificates"
    );
    Ok(())
}

/// Writes `server.pem` / `server-key.pem` for the given DNS names / IPs (CA created if absent).
pub fn init(out: &Path, names: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !names.is_empty(),
        "give at least one --name (DNS name or IP agents use to reach the server)"
    );
    let mut p = CertificateParams::new(names.to_vec())?;
    p.distinguished_name
        .push(DnType::CommonName, names[0].clone());
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // Rotate by re-running `cert init`; agents keep trusting the same CA.
    issue(out, "server", p, 2)
}

/// Writes `tech-<name>.pem` / `tech-<name>-key.pem`: a client certificate agents accept for direct
/// management. The certificate's CN is the technician name agents authorize and log.
pub fn tech(out: &Path, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._@-".contains(c)),
        "technician name must be 1-64 chars of A-Z a-z 0-9 . _ @ -"
    );
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.distinguished_name.push(DnType::CommonName, name);
    // ClientAuth only: this certificate cannot be used to impersonate a server.
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    // shortcut: no CRL; revoke by removing the name from agents' allowed_technicians and let it expire (1 year).
    issue(out, &format!("tech-{name}"), p, 1)
}
