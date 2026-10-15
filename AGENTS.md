# AGENTS.md — conventions for every contributor (Claude Code, Codex, humans)

Requirements live in [PLAN.md](PLAN.md). Work is tracked in [TASKS.md](TASKS.md) — **read its "How to use" section first; claim a task before coding.**

## Layout

| Path | What |
|---|---|
| `crates/protocol` | Wire types + protocol version. The only crate all apps share. Changing a type here is a protocol change: additive → bump minor, breaking → bump major in `PROTOCOL_VERSION`. |
| `apps/server` | `tervano-server`: axum + sqlx/SQLite. `src/lib.rs` = API, `src/main.rs` = CLI, `migrations/` = schema, `tests/api.rs` = in-process API tests. |
| `apps/agent` | `TervanoAgent.exe`: `collect.rs` (OS data), `service.rs` (SCM), `main.rs` (config, enroll, report loop). |
| `apps/console` | `TervanoConsole.exe`: Iced 0.14 GUI. `api.rs` = server client. |

Add a new crate under `crates/` only when two apps need the same non-wire code. Don't pre-create the crates listed in PLAN §4 until there is code for them.

## Build & test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

All four must be clean before pushing to `main`. Windows (MSVC) is the primary target; the server must also build on Linux.

Local end-to-end run: see README "Quick start". Put scratch DBs/configs in `dev-data/` (git-ignored).

## Rules

- **Rust 2024 edition**, stable toolchain. Pin new deps to a major (`"0.8"`), commit `Cargo.lock`. Justify every new dependency in the commit message; prefer std / existing deps.
- **No fake data in production code paths.** Mocks only in tests.
- **Security is not optional** (PLAN §12): authn on every endpoint except `/healthz` `/readyz`; validate input at trust boundaries; store only hashes of secrets server-side; never log secrets; no hidden remote sessions.
- **`unsafe`** only for FFI, each block with a `// SAFETY:` comment.
- **Shortcuts** must be marked `// shortcut: <limit>, <task id that removes it>` and have a TASKS.md entry.
- Errors: `anyhow` in binaries, typed/`AppError` at the HTTP boundary. Don't `unwrap()` on anything input-derived.
- Logging: `tracing`, honour `RUST_LOG`.
- Comments explain *why*, not *what*.
- Tests: new server endpoints get a case in `apps/server/tests/api.rs`; new protocol types get a serde round-trip test.

## Git

- Trunk-based on `main`; small commits; Conventional Commit subjects (`feat(server): …`, `fix(agent): …`, `chore(tasks): …`).
- Pull/rebase before pushing — the other agent pushes too. Never force-push `main`.
- Update TASKS.md (status + verification note) in the same commit as the feature. Update README status table when a user-visible feature changes.
- Don't edit files under a crate where the other agent has an in-progress task without noting it in TASKS.md.

## Honesty rules (from PLAN)

- "Implemented" means working code + passing acceptance. Compiling is not evidence.
- Windows behaviour (sessions, service, capture, input) must be run on Windows before it's marked done. Record what OS it was tested on.
- Never fabricate test results, benchmarks, or competitor claims.
