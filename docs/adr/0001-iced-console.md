# ADR-0001: Iced for the native Console

- Status: Accepted (recorded 2026-10-15)
- Scope: `apps/console`

## Context

The technician Console needs a native, responsive Windows desktop UI in the Rust workspace. The project avoids shipping an embedded browser runtime and needs asynchronous device search and live updates without blocking the UI. [PLAN.md](../../PLAN.md) §3 prefers Iced but also names Slint and native Windows UI as options.

## Decision

Use the stable Iced 0.14 crate for the Console. Keep network requests in asynchronous tasks/subscriptions and keep the shared wire model in `crates/protocol`. The current Console already uses Iced for search, device details, settings, and direct Agent access.

## Consequences

- One Rust UI stack and lockfile serve the initial Windows build; no browser runtime is required.
- Iced and its renderer add a substantial dependency/build footprint. Desktop accessibility, keyboard behavior, and rendering performance still need validation (T-955, T-307, T-308).
- This records the implemented choice, not a completed comparative benchmark against Slint or native Windows controls. Revisit it if measured UX or platform constraints make Iced unsuitable.
