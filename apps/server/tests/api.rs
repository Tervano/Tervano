//! In-process API tests: enroll → events → search, plus auth/replay checks.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::Duration;
use tervano_protocol::*;
use tervano_server::*;
use tower::ServiceExt;

async fn setup() -> (Router, sqlx::SqlitePool) {
    let db = connect("sqlite::memory:").await.unwrap();
    (
        app(AppState {
            db: db.clone(),
            offline_after_ms: 180_000,
        }),
        db,
    )
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(PROTOCOL_HEADER, PROTOCOL_VERSION);
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn state(host: &str, user: &str, ip: &str) -> DeviceState {
    DeviceState {
        hostname: host.into(),
        domain: Some("corp.example".into()),
        os: OsInfo {
            name: "Windows 11 Pro".into(),
            version: "10.0".into(),
            build: "26200".into(),
        },
        addresses: vec![NetAddress {
            interface: "Ethernet".into(),
            address: ip.into(),
        }],
        sessions: vec![UserSession {
            session_id: 1,
            username: user.into(),
            domain: "CORP".into(),
            state: SessionState::Active,
            station: "Console".into(),
        }],
        agent_version: "0.1.0".into(),
    }
}

async fn enroll(app: &Router, db: &sqlx::SqlitePool, st: &DeviceState) -> EnrollResponse {
    let token = create_enrollment_token(db, 1, Duration::from_secs(60))
        .await
        .unwrap();
    let (code, body) = call(
        app,
        "POST",
        "/api/v1/enroll",
        None,
        Some(json!({ "token": token, "state": st })),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

#[tokio::test]
async fn enroll_report_search() {
    let (app, db) = setup().await;
    let tech = create_technician(&db, "alice").await.unwrap();
    let dev = enroll(&app, &db, &state("PC-LAB-01", "jdoe", "10.0.0.5")).await;
    enroll(&app, &db, &state("PC-OFFICE-02", "asmith", "10.0.0.9")).await;

    // Search by hostname prefix (case-insensitive), user, DOMAIN\user, IP.
    for q in ["pc-lab", "jdoe", "CORP%5Cjdoe", "10.0.0.5"] {
        let (code, body) = call(
            &app,
            "GET",
            &format!("/api/v1/devices?q={q}"),
            Some(&tech),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        let hits: Vec<DeviceSummary> = serde_json::from_value(body).unwrap();
        assert_eq!(hits.len(), 1, "query {q}");
        assert_eq!(hits[0].hostname, "PC-LAB-01");
        assert!(hits[0].online);
        assert_eq!(hits[0].primary_ip.as_deref(), Some("10.0.0.5"));
    }

    // User logs off, new user logs on, IP changes → index follows.
    let ev = AgentEvent {
        seq: 1,
        at: 0,
        kind: EventKind::StateChanged {
            state: state("PC-LAB-01", "bwayne", "10.0.7.7"),
        },
    };
    let (code, ack) = call(
        &app,
        "POST",
        "/api/v1/events",
        Some(&dev.device_secret),
        Some(json!([ev])),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(ack["last_seq"], 1);
    let (_, body) = call(&app, "GET", "/api/v1/devices?q=jdoe", Some(&tech), None).await;
    assert_eq!(body.as_array().unwrap().len(), 0);
    let (_, body) = call(&app, "GET", "/api/v1/devices?q=10.0.7", Some(&tech), None).await;
    assert_eq!(body[0]["users"], json!(["bwayne"]));

    // Details.
    let (code, body) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{}", dev.device_id),
        Some(&tech),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let d: DeviceDetails = serde_json::from_value(body).unwrap();
    assert_eq!(d.state.sessions[0].username, "bwayne");

    // Wildcards are literal.
    let (_, body) = call(&app, "GET", "/api/v1/devices?q=%25", Some(&tech), None).await;
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn replayed_events_are_ignored_and_shutdown_marks_offline() {
    let (app, db) = setup().await;
    let tech = create_technician(&db, "alice").await.unwrap();
    let dev = enroll(&app, &db, &state("PC-1", "jdoe", "10.0.0.5")).await;

    let newer = AgentEvent {
        seq: 5,
        at: 0,
        kind: EventKind::StateChanged {
            state: state("PC-1", "new", "10.0.0.5"),
        },
    };
    let older = AgentEvent {
        seq: 3,
        at: 0,
        kind: EventKind::StateChanged {
            state: state("PC-1", "old", "10.0.0.5"),
        },
    };
    call(
        &app,
        "POST",
        "/api/v1/events",
        Some(&dev.device_secret),
        Some(json!([newer])),
    )
    .await;
    let (_, ack) = call(
        &app,
        "POST",
        "/api/v1/events",
        Some(&dev.device_secret),
        Some(json!([older, newer])),
    )
    .await;
    assert_eq!(ack["last_seq"], 5);
    let (_, body) = call(&app, "GET", "/api/v1/devices?q=PC-1", Some(&tech), None).await;
    assert_eq!(body[0]["users"], json!(["new"]));

    let bye = AgentEvent {
        seq: 6,
        at: 0,
        kind: EventKind::Shutdown,
    };
    call(
        &app,
        "POST",
        "/api/v1/events",
        Some(&dev.device_secret),
        Some(json!([bye])),
    )
    .await;
    let (_, body) = call(&app, "GET", "/api/v1/devices?q=PC-1", Some(&tech), None).await;
    assert_eq!(body[0]["online"], false);
}

#[tokio::test]
async fn auth_is_enforced() {
    let (app, db) = setup().await;
    let st = state("PC-1", "jdoe", "10.0.0.5");

    // Bad and reused enrollment tokens.
    let (code, _) = call(
        &app,
        "POST",
        "/api/v1/enroll",
        None,
        Some(json!({ "token": "nope", "state": st })),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let token = create_enrollment_token(&db, 1, Duration::from_secs(60))
        .await
        .unwrap();
    let body = json!({ "token": token, "state": st });
    assert_eq!(
        call(&app, "POST", "/api/v1/enroll", None, Some(body.clone()))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "POST", "/api/v1/enroll", None, Some(body))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    // Expired token.
    let expired = create_enrollment_token(&db, 1, Duration::ZERO)
        .await
        .unwrap();
    let (code, _) = call(
        &app,
        "POST",
        "/api/v1/enroll",
        None,
        Some(json!({ "token": expired, "state": st })),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);

    // Device secrets are not technician tokens and vice versa.
    let dev = enroll(&app, &db, &st).await;
    assert_eq!(
        call(
            &app,
            "GET",
            "/api/v1/devices",
            Some(&dev.device_secret),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/api/v1/devices", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let tech = create_technician(&db, "alice").await.unwrap();
    assert_eq!(
        call(&app, "POST", "/api/v1/events", Some(&tech), Some(json!([])))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // Protocol header required and checked.
    let req = Request::get("/api/v1/devices")
        .header(PROTOCOL_HEADER, "2.0")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let req = Request::get("/healthz").body(Body::empty()).unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
}
