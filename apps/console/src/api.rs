//! Tervano Server API client. Errors are strings because they go straight to the UI.

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
        let http = builder
            .https_only(!base.starts_with("http://"))
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T, String> {
        let res = req.bearer_auth(&self.token).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                format!("Cannot reach Tervano Server at {}. Check Settings and that the server is running.", self.base)
            } else {
                e.to_string()
            }
        })?;
        let status = res.status();
        if status.is_success() {
            return res
                .json()
                .await
                .map_err(|e| format!("Unexpected server response: {e}"));
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

    pub async fn search(&self, q: &str) -> Result<Vec<DeviceSummary>, String> {
        self.get(
            self.http
                .get(format!("{}/api/v1/devices", self.base))
                .query(&[("q", q)]),
        )
        .await
    }

    pub async fn details(&self, id: uuid::Uuid) -> Result<DeviceDetails, String> {
        self.get(self.http.get(format!("{}/api/v1/devices/{id}", self.base)))
            .await
    }
}
