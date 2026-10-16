//! Tervano Server API client. Errors are strings because they go straight to the UI.

use iced::futures::{SinkExt, Stream, channel::mpsc};
use std::time::Duration;
use tervano_protocol::*;

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Client {
    pub fn new(base: &str, token: &str, ca_cert: &str) -> Result<Self, String> {
        Self::build(base, token, ca_cert, Some(Duration::from_secs(10)))
    }

    /// `timeout` bounds a whole request; `None` for long-lived streams.
    fn build(
        base: &str,
        token: &str,
        ca_cert: &str,
        timeout: Option<Duration>,
    ) -> Result<Self, String> {
        if !url_transport_ok(base) {
            return Err(format!(
                "Server URL {base} must start with https:// (http:// is only allowed for localhost)."
            ));
        }
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            PROTOCOL_HEADER,
            reqwest::header::HeaderValue::from_static(PROTOCOL_VERSION),
        );
        let mut builder = reqwest::Client::builder();
        if !ca_cert.is_empty() {
            let pem = std::fs::read(ca_cert)
                .map_err(|e| format!("Cannot read CA certificate {ca_cert}: {e}"))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| format!("Invalid CA certificate {ca_cert}: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        if let Some(t) = timeout {
            builder = builder.timeout(t);
        }
        let http = builder
            .https_only(!base.starts_with("http://"))
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
        })
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, String> {
        let res = req.bearer_auth(&self.token).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                format!("Cannot reach Tervano Server at {}. Check Settings and that the server is running.", self.base)
            } else {
                e.to_string()
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
            401 => "The server rejected your technician token. Update it in Settings.".into(),
            _ => format!("Server error {status}: {msg}"),
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T, String> {
        self.send(req)
            .await?
            .json()
            .await
            .map_err(|e| format!("Unexpected server response: {e}"))
    }

    pub async fn search(&self, q: &str) -> Result<Vec<DeviceSummary>, String> {
        self.get(
            self.http
                .get(format!("{}/api/v1/devices", self.base))
                .query(&[("q", q)]),
        )
        .await
    }

    /// Latest inventory snapshot the agent sent; `None` until it has sent one.
    pub async fn inventory(&self, id: uuid::Uuid) -> Result<Option<InventoryReport>, String> {
        // Connection errors surface through the details call; keep this one terse.
        let res = self
            .http
            .get(format!("{}/api/v1/devices/{id}/inventory", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        match res.status() {
            // Nothing received yet is normal for a newly enrolled agent.
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            s if s.is_success() => res
                .json()
                .await
                .map(Some)
                .map_err(|e| format!("Unexpected server response: {e}")),
            s => Err(format!("server error {s}")),
        }
    }

    pub async fn details(&self, id: uuid::Uuid) -> Result<DeviceDetails, String> {
        self.get(self.http.get(format!("{}/api/v1/devices/{id}", self.base)))
            .await
    }

    pub async fn create_job(&self, job: &JobCreate) -> Result<JobSummary, String> {
        self.get(
            self.http
                .post(format!("{}/api/v1/jobs", self.base))
                .json(job),
        )
        .await
    }

    pub async fn jobs(&self) -> Result<Vec<JobSummary>, String> {
        self.get(self.http.get(format!("{}/api/v1/jobs", self.base)))
            .await
    }

    pub async fn job(&self, id: uuid::Uuid) -> Result<JobDetail, String> {
        self.get(self.http.get(format!("{}/api/v1/jobs/{id}", self.base)))
            .await
    }

    pub async fn cancel_job(&self, id: uuid::Uuid) -> Result<JobSummary, String> {
        self.get(
            self.http
                .post(format!("{}/api/v1/jobs/{id}/cancel", self.base)),
        )
        .await
    }
}

#[derive(Debug, Clone)]
pub enum LiveEvent {
    Connected,
    Disconnected(String),
    Changed(uuid::Uuid),
    /// Events were missed; reload everything.
    Resync,
}

/// `(server_url, token, ca_cert)`; a change in any of them restarts the stream.
pub type LiveKey = (String, String, String);

/// Follows `GET /api/v1/stream`, reconnecting with backoff, for as long as the subscription lives.
pub fn live(key: &LiveKey) -> impl Stream<Item = LiveEvent> + use<> {
    let (base, token, ca) = key.clone();
    iced::stream::channel(64, async move |mut out: mpsc::Sender<LiveEvent>| {
        let mut backoff = Duration::from_secs(1);
        loop {
            let result = match Client::build(&base, &token, &ca, None) {
                Ok(c) => follow(&c, &mut out, &mut backoff).await,
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                let _ = out.send(LiveEvent::Disconnected(e)).await;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    })
}

/// Reads one SSE connection until it fails or goes quiet.
async fn follow(
    c: &Client,
    out: &mut mpsc::Sender<LiveEvent>,
    backoff: &mut Duration,
) -> Result<(), String> {
    let mut res = c
        .send(
            c.http
                .get(format!("{}/api/v1/stream", c.base))
                .header("accept", "text/event-stream"),
        )
        .await?;
    *backoff = Duration::from_secs(1);
    let _ = out.send(LiveEvent::Connected).await;
    let mut buf = String::new();
    loop {
        // The server sends keep-alives every 15 s; silence beyond this means a dead connection.
        let chunk = tokio::time::timeout(Duration::from_secs(45), res.chunk())
            .await
            .map_err(|_| "Live updates timed out".to_string())?
            .map_err(|e| format!("Connection to server lost ({e})"))?
            .ok_or("Server closed the live update stream")?;
        buf.push_str(&String::from_utf8_lossy(&chunk).replace("\r\n", "\n"));
        while let Some(end) = buf.find("\n\n") {
            let block: String = buf.drain(..end + 2).collect();
            if let Some(ev) = parse_event(&block) {
                let _ = out.send(ev).await;
            }
        }
    }
}

/// Parses one SSE event block (`event:` + `data:` lines; `:` lines are keep-alive comments).
fn parse_event(block: &str) -> Option<LiveEvent> {
    let (mut name, mut data) = ("", "");
    for line in block.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            name = v.trim();
        } else if let Some(v) = line.strip_prefix("data:") {
            data = v.trim();
        }
    }
    match name {
        STREAM_DEVICE => serde_json::from_str::<DeviceChanged>(data)
            .ok()
            .map(|d| LiveEvent::Changed(d.id)),
        STREAM_RESYNC => Some(LiveEvent::Resync),
        _ => None,
    }
}
