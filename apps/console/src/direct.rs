//! Direct (serverless) agent access: mutual TLS with the technician's certificate; the agent is
//! trusted only by its pinned SHA-256 certificate fingerprint (PLAN §2A, §12).

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use rustls::{DigitallySignedStruct, SignatureScheme, crypto::CryptoProvider};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tervano_protocol::*;

pub const DEFAULT_PORT: u16 = 8472;

/// `host` → `host:8472`; `host:port` and `[v6]:port` unchanged.
pub fn normalize_address(a: &str) -> String {
    let a = a.trim();
    let has_port = match a.strip_prefix('[') {
        Some(rest) => rest.contains("]:"),
        None => a.matches(':').count() == 1,
    };
    if has_port {
        a.to_owned()
    } else if a.contains(':') && !a.starts_with('[') {
        format!("[{a}]:{DEFAULT_PORT}") // bare IPv6
    } else {
        format!("{a}:{DEFAULT_PORT}")
    }
}

/// Lowercase hex without separators, so pins compare regardless of how they were typed.
pub fn normalize_fingerprint(f: &str) -> String {
    f.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// `af62 3774 …` for reading aloud / comparing by eye.
pub fn display_fingerprint(f: &str) -> String {
    f.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Accepts exactly the pinned certificate; always records what the agent presented.
#[derive(Debug)]
struct Pinned {
    pin: Option<String>,
    seen: Mutex<Option<String>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = hex::encode(Sha256::digest(end_entity.as_ref()));
        let ok = self.pin.as_deref() == Some(fp.as_str());
        *self.seen.lock().expect("not poisoned") = Some(fp);
        // A probe (no pin) always aborts here: nothing is exchanged until the technician confirms.
        if ok {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "agent certificate not pinned".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Technician identity: paths to the PEM certificate and key from `tervano-server cert tech`.
#[derive(Debug, Clone)]
pub struct Creds {
    pub cert: String,
    pub key: String,
}

fn client(creds: &Creds, verifier: Arc<Pinned>) -> Result<reqwest::Client, String> {
    if creds.cert.is_empty() || creds.key.is_empty() {
        return Err(
            "Set your technician certificate and key in Settings to use direct connections.".into(),
        );
    }
    let chain = CertificateDer::pem_file_iter(&creds.cert)
        .and_then(|i| i.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("Cannot read technician certificate {}: {e}", creds.cert))?;
    let key = PrivateKeyDer::from_pem_file(&creds.key)
        .map_err(|e| format!("Cannot read technician key {}: {e}", creds.key))?;
    let mut tls = rustls::ClientConfig::builder_with_provider(verifier.provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("Technician certificate/key mismatch: {e}"))?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        PROTOCOL_HEADER,
        reqwest::header::HeaderValue::from_static(PROTOCOL_VERSION),
    );
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .default_headers(headers)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())
}

fn verifier(pin: Option<String>) -> Arc<Pinned> {
    Arc::new(Pinned {
        pin,
        seen: Mutex::new(None),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    })
}

/// Connects far enough to read the agent's certificate fingerprint (trust on first use).
pub async fn probe(address: String, creds: Creds) -> Result<String, String> {
    let v = verifier(None);
    let c = client(&creds, v.clone())?;
    let r = c.get(format!("https://{address}/v1/device")).send().await;
    match (v.seen.lock().expect("not poisoned").clone(), r) {
        (Some(fp), _) => Ok(fp),
        (None, Err(e)) => Err(format!("Cannot reach agent at {address}: {e}")),
        (None, Ok(_)) => Err("Unexpected: agent answered without presenting a certificate".into()),
    }
}

/// One pinned agent plus the technician identity used to reach it.
#[derive(Debug, Clone)]
pub struct Target {
    pub address: String,
    pub pin: String,
    pub creds: Creds,
}

/// Sends one request to a pinned agent and turns transport/HTTP failures into readable text.
async fn send(
    t: &Target,
    build: impl FnOnce(&reqwest::Client, String) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, String> {
    let v = verifier(Some(t.pin.clone()));
    let c = client(&t.creds, v.clone())?;
    let address = &t.address;
    let res = build(&c, format!("https://{address}"))
        .send()
        .await
        .map_err(|e| {
            match v.seen.lock().expect("not poisoned").as_deref() {
                Some(seen) if seen != t.pin => format!(
                    "Certificate changed! {address} now presents {} but {} is pinned. This can mean                      interception, or that the agent was reinstalled. Verify with                      `TervanoAgent direct-fingerprint` on the endpoint before re-adding it.",
                    display_fingerprint(seen),
                    display_fingerprint(&t.pin)
                ),
                // Handshake passed our check, so a failure now is the agent refusing us or the network.
                Some(_) => format!(
                    "The agent at {address} refused the connection. Is your technician certificate                      issued by the CA it trusts? ({e})"
                ),
                None => format!("Cannot reach agent at {address}: {e}"),
            }
        })?;
    let status = res.status();
    if status.is_success() {
        return Ok(res);
    }
    let msg = res
        .json::<ApiError>()
        .await
        .map(|e| e.error)
        .unwrap_or_default();
    Err(match status.as_u16() {
        403 => format!("Not authorized: {msg}"),
        409 => msg,
        _ => format!("Agent error {status}: {msg}"),
    })
}

async fn json<T: serde::de::DeserializeOwned>(res: reqwest::Response) -> Result<T, String> {
    res.json()
        .await
        .map_err(|e| format!("Unexpected agent response: {e}"))
}

/// Reads live device state from the agent, refusing anything but the pinned certificate.
pub async fn device(t: Target) -> Result<DeviceState, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/device"))).await?).await
}

pub async fn processes(t: Target) -> Result<Vec<ProcessInfo>, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/processes"))).await?).await
}

/// Terminates `pid` only if it is still named `name` on the agent.
pub async fn kill(t: Target, pid: u32, name: String) -> Result<(), String> {
    send(&t, |c, base| {
        c.post(format!("{base}/v1/processes/{pid}/kill"))
            .json(&KillRequest { name })
    })
    .await
    .map(|_| ())
}
