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

/// Writes `ca.pem`, `ca-key.pem` (only if absent), `server.pem` (leaf + CA chain) and `server-key.pem`.
pub fn init(out: &Path, names: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !names.is_empty(),
        "give at least one --name (DNS name or IP agents use to reach the server)"
    );
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
            "created CA: {} (distribute to agents/consoles as ca_cert)",
            ca_cert_path.display()
        );
        key
    };
    let ca_pem =
        std::fs::read_to_string(&ca_cert_path).context("ca.pem missing next to ca-key.pem")?;
    let issuer = Issuer::new(ca_params()?, &ca_key);

    let y = year_now();
    let mut p = CertificateParams::new(names.to_vec())?;
    p.distinguished_name
        .push(DnType::CommonName, names[0].clone());
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.not_before = rcgen::date_time_ymd(y - 1, 1, 1);
    // Rotate by re-running `cert init`; agents keep trusting the same CA.
    p.not_after = rcgen::date_time_ymd(y + 2, 1, 1);
    let key = KeyPair::generate()?;
    let cert = p.signed_by(&key, &issuer)?;

    std::fs::write(out.join("server.pem"), format!("{}{}", cert.pem(), ca_pem))?;
    write_private(&out.join("server-key.pem"), &key.serialize_pem())?;
    println!(
        "wrote {} and {} for {}",
        out.join("server.pem").display(),
        out.join("server-key.pem").display(),
        names.join(", ")
    );
    println!("keep ca-key.pem offline-safe: anyone holding it can impersonate this server");
    Ok(())
}
