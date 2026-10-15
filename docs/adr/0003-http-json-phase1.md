# ADR-0003: HTTP and JSON for Phase 1 control APIs

- Status: Accepted for Phase 1 (recorded 2026-10-15)
- Scope: Server API and current direct Agent read API

## Context

Enrollment, event ingestion, search, device details, audit, and direct device reads are small control messages. They need an inspectable transport while the product's remote-session architecture is still planned. [PLAN.md](../../PLAN.md) §3 lists gRPC and QUIC as possible later transports.

## Decision

Use typed HTTP+JSON endpoints with shared Serde wire types in `crates/protocol`. Require `X-Tervano-Protocol`; increment its minor version for additive wire changes and major version for breaking changes. Use TLS off loopback, bearer credentials for the current Server API, and mutual TLS plus certificate pinning for direct Console → Agent reads. Use Server-Sent Events for current device-change notifications.

## Consequences

- Requests and failures can be inspected with ordinary HTTP tools, and the existing Agent, Server, and Console share one wire contract.
- JSON state snapshots have bandwidth/storage costs; body limits, idempotent event sequences, pagination, and event retention bound parts of that cost. The current header checks major compatibility, not full feature negotiation.
- This decision does not choose a screen-streaming codec or transport. Remote frames/input must use an encrypted transport suitable for their latency and bandwidth needs; QUIC with TCP/TLS fallback remains planned (T-404).
