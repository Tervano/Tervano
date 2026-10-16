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
                    "Certificate changed! {address} now presents {} but {} is pinned. This can mean \
                     interception, or that the agent was reinstalled. Verify with \
                     `TervanoAgent direct-fingerprint` on the endpoint before re-adding it.",
                    display_fingerprint(seen),
                    display_fingerprint(&t.pin)
                ),
                // Handshake passed our check, so a failure now is the agent refusing us or the network.
                Some(_) => format!(
                    "The agent at {address} refused the connection. Is your technician certificate \
                     issued by the CA it trusts? ({e})"
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

pub async fn services(t: Target) -> Result<Vec<ServiceEntry>, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/services"))).await?).await
}

/// Starts/stops/pauses/resumes/restarts a service; the agent waits for it to settle.
pub async fn control_service(
    t: Target,
    name: String,
    action: ServiceAction,
) -> Result<ServiceEntry, String> {
    let res = send(&t, |c, base| {
        c.post(format!("{base}/v1/services/{name}/control"))
            .json(&ServiceControlRequest { action })
            // Restart waits for stop + start on the agent (up to 30 s each).
            .timeout(Duration::from_secs(75))
    })
    .await?;
    json(res).await
}

pub async fn set_start_type(
    t: Target,
    name: String,
    start_type: StartType,
) -> Result<ServiceEntry, String> {
    let res = send(&t, |c, base| {
        c.post(format!("{base}/v1/services/{name}/start-type"))
            .json(&StartTypeRequest { start_type })
    })
    .await?;
    json(res).await
}

pub async fn event_channels(t: Target) -> Result<Vec<String>, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/eventlog/channels"))).await?).await
}

pub async fn events(t: Target, q: EventQuery) -> Result<Vec<EventRecord>, String> {
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/eventlog/events")).query(&q)
        })
        .await?,
    )
    .await
}

pub async fn hardware(t: Target) -> Result<HardwareInventory, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/inventory/hardware"))).await?).await
}

pub async fn software(t: Target) -> Result<SoftwareInventory, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/inventory/software"))).await?).await
}

pub async fn reg_key(t: Target, k: RegKeyPath) -> Result<RegKeyContents, String> {
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/registry/key")).query(&k)
        })
        .await?,
    )
    .await
}

/// `.reg` text of the key and everything below it.
pub async fn reg_export(t: Target, k: RegKeyPath) -> Result<String, String> {
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/registry/export")).query(&k)
        })
        .await?,
    )
    .await
}

pub async fn reg_set(t: Target, req: RegSetValueRequest) -> Result<(), String> {
    send(&t, |c, base| {
        c.post(format!("{base}/v1/registry/value")).json(&req)
    })
    .await
    .map(|_| ())
}

pub async fn reg_delete_value(t: Target, req: RegDeleteValueRequest) -> Result<(), String> {
    send(&t, |c, base| {
        c.post(format!("{base}/v1/registry/value/delete"))
            .json(&req)
    })
    .await
    .map(|_| ())
}

pub async fn reg_delete_key(t: Target, req: RegDeleteKeyRequest) -> Result<(), String> {
    send(&t, |c, base| {
        c.post(format!("{base}/v1/registry/key/delete")).json(&req)
    })
    .await
    .map(|_| ())
}

pub async fn exec_start(t: Target, req: ExecRequest) -> Result<ExecStatus, String> {
    json(send(&t, |c, base| c.post(format!("{base}/v1/exec")).json(&req)).await?).await
}

pub async fn exec_status(t: Target, id: uuid::Uuid) -> Result<ExecStatus, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/exec/{id}"))).await?).await
}

pub async fn exec_cancel(t: Target, id: uuid::Uuid) -> Result<(), String> {
    send(&t, |c, base| c.post(format!("{base}/v1/exec/{id}/cancel")))
        .await
        .map(|_| ())
}

pub async fn files_list(t: Target, path: String) -> Result<DirListing, String> {
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/files/list"))
                .query(&FilePathQuery { path })
        })
        .await?,
    )
    .await
}

pub async fn files_op(t: Target, op: FileOp) -> Result<(), String> {
    send(&t, |c, base| {
        c.post(format!("{base}/v1/files/op")).json(&op)
    })
    .await
    .map(|_| ())
}

/// Per-chunk timeout: 8 MiB over a slow link takes far longer than ordinary API calls.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(300);

/// Retries a chunk transfer a few times so a dropped connection resumes instead of failing.
async fn retry<T, F: std::future::Future<Output = Result<T, String>>>(
    mut f: impl FnMut() -> F,
) -> Result<T, String> {
    let mut last = String::new();
    for attempt in 0..3 {
        match f().await {
            Ok(v) => return Ok(v),
            // Authorization and validation errors won't fix themselves.
            Err(e) if e.starts_with("Not authorized") || e.starts_with("Certificate changed") => {
                return Err(e);
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
    }
    Err(last)
}

/// Downloads `remote` into `local_dir` in resumable chunks and verifies size and SHA-256 against
/// the agent's hash before the file appears under its final name. Never overwrites a local file.
pub async fn download(
    t: Target,
    remote: String,
    local_dir: std::path::PathBuf,
) -> Result<String, String> {
    let name = remote
        .rsplit(['\\', '/'])
        .next()
        .filter(|n| !n.is_empty())
        .ok_or("not a file path")?
        .to_owned();
    let mut local = local_dir.join(&name);
    for n in 1.. {
        if !local.exists() {
            break;
        }
        local = local_dir.join(format!("{name} ({n})"));
    }
    let part = local.with_extension(format!(
        "{}tervano-part",
        local
            .extension()
            .map(|e| format!("{}.", e.to_string_lossy()))
            .unwrap_or_default()
    ));
    // Any failure removes the partial file so nothing half-written is left behind.
    let result: Result<u64, String> = async {
        let mut out = std::fs::File::create(&part)
            .map_err(|e| format!("cannot create {}: {e}", part.display()))?;
        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        loop {
            let (bytes, size) = retry(|| {
                let (t, path) = (t.clone(), remote.clone());
                async move {
                    let res = send(&t, |c, base| {
                        c.get(format!("{base}/v1/files/read"))
                            .query(&FileChunkQuery {
                                path,
                                offset,
                                len: None,
                            })
                            .timeout(CHUNK_TIMEOUT)
                    })
                    .await?;
                    let size: u64 = res
                        .headers()
                        .get(FILE_SIZE_HEADER)
                        .and_then(|v| v.to_str().ok()?.parse().ok())
                        .ok_or("agent did not report the file size")?;
                    let bytes = res.bytes().await.map_err(|e| e.to_string())?;
                    Ok((bytes, size))
                }
            })
            .await?;
            std::io::Write::write_all(&mut out, &bytes)
                .map_err(|e| format!("cannot write {}: {e}", part.display()))?;
            hasher.update(&bytes);
            offset += bytes.len() as u64;
            if bytes.is_empty() || offset >= size {
                break;
            }
        }
        drop(out);
        let remote_hash: FileHash = json(
            send(&t, |c, base| {
                c.get(format!("{base}/v1/files/hash"))
                    .query(&FilePathQuery {
                        path: remote.clone(),
                    })
                    .timeout(CHUNK_TIMEOUT)
            })
            .await?,
        )
        .await?;
        let local_hash = hex::encode(hasher.finalize());
        if remote_hash.size != offset || remote_hash.sha256 != local_hash {
            return Err(format!(
                "download did not verify (got {offset} bytes, SHA-256 {local_hash}; agent has {} bytes, {}). The file may have changed during the transfer; try again.",
                remote_hash.size, remote_hash.sha256
            ));
        }
        Ok(offset)
    }
    .await;
    let offset = match result {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
    };
    std::fs::rename(&part, &local)
        .map_err(|e| format!("cannot finish {}: {e}", local.display()))?;
    Ok(format!(
        "Downloaded {} ({} bytes, SHA-256 verified) to {}",
        name,
        offset,
        local.display()
    ))
}

/// Uploads `local` as `remote` in resumable chunks; the agent only moves it into place if the
/// SHA-256 matches.
pub async fn upload(
    t: Target,
    local: std::path::PathBuf,
    remote: String,
    overwrite: bool,
) -> Result<String, String> {
    use std::io::Read;
    let mut f =
        std::fs::File::open(&local).map_err(|e| format!("cannot open {}: {e}", local.display()))?;
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    let mut buf = vec![0u8; FILE_CHUNK_MAX as usize];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {e}", local.display()))?;
        // Always send at least one chunk so empty files are created too.
        if n == 0 && offset > 0 {
            break;
        }
        let chunk = buf[..n].to_vec();
        hasher.update(&chunk);
        let p: UploadProgress = retry(|| {
            let (t, path, chunk) = (t.clone(), remote.clone(), chunk.clone());
            async move {
                json(
                    send(&t, |c, base| {
                        c.post(format!("{base}/v1/files/upload"))
                            .query(&FileChunkQuery {
                                path,
                                offset,
                                len: None,
                            })
                            .body(chunk)
                            .timeout(CHUNK_TIMEOUT)
                    })
                    .await?,
                )
                .await
            }
        })
        .await?;
        offset = p.part_size;
        if n == 0 {
            break;
        }
    }
    let sha256 = hex::encode(hasher.finalize());
    let done: FileHash = json(
        send(&t, |c, base| {
            c.post(format!("{base}/v1/files/upload/finish"))
                .json(&UploadFinish {
                    path: remote.clone(),
                    sha256: sha256.clone(),
                    overwrite,
                })
                .timeout(CHUNK_TIMEOUT)
        })
        .await?,
    )
    .await?;
    Ok(format!(
        "Uploaded {} ({} bytes, SHA-256 verified) to {remote}",
        local.display(),
        done.size
    ))
}

pub async fn software_uninstall(t: Target, req: UninstallRequest) -> Result<ExecStatus, String> {
    json(
        send(&t, |c, base| {
            c.post(format!("{base}/v1/software/uninstall")).json(&req)
        })
        .await?,
    )
    .await
}

pub async fn software_install(t: Target, req: InstallRequest) -> Result<ExecStatus, String> {
    json(
        send(&t, |c, base| {
            c.post(format!("{base}/v1/software/install")).json(&req)
        })
        .await?,
    )
    .await
}

pub async fn peripherals(t: Target) -> Result<Peripherals, String> {
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/inventory/peripherals"))
        })
        .await?,
    )
    .await
}

pub async fn wmi_query(t: Target, q: WmiQuery) -> Result<WmiTable, String> {
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/wmi/query")).query(&q)
        })
        .await?,
    )
    .await
}

pub async fn wmi_classes(t: Target, namespace: String) -> Result<Vec<String>, String> {
    let q = WmiQuery {
        namespace: Some(namespace),
        wql: String::new(),
    };
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/wmi/classes")).query(&q)
        })
        .await?,
    )
    .await
}

pub async fn updates(t: Target) -> Result<UpdateStatus, String> {
    json(send(&t, |c, base| c.get(format!("{base}/v1/updates"))).await?).await
}

pub async fn terminal_open(t: Target, shell: Shell) -> Result<TerminalOutput, String> {
    json(
        send(&t, |c, base| {
            c.post(format!("{base}/v1/terminal"))
                .json(&TerminalStart { shell })
        })
        .await?,
    )
    .await
}

pub async fn terminal_input(t: Target, id: uuid::Uuid, text: String) -> Result<(), String> {
    send(&t, |c, base| {
        c.post(format!("{base}/v1/terminal/{id}/input"))
            .json(&TerminalInput { text })
    })
    .await
    .map(|_| ())
}

pub async fn terminal_output(
    t: Target,
    id: uuid::Uuid,
    since: u64,
) -> Result<TerminalOutput, String> {
    json(
        send(&t, |c, base| {
            c.get(format!("{base}/v1/terminal/{id}/output"))
                .query(&TerminalSince { since })
        })
        .await?,
    )
    .await
}

pub async fn terminal_close(t: Target, id: uuid::Uuid) -> Result<(), String> {
    send(&t, |c, base| {
        c.post(format!("{base}/v1/terminal/{id}/close"))
    })
    .await
    .map(|_| ())
}
