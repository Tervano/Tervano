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

## Build

**Testing is deferred for now (PLAN.md, 2026-10-14): don't write new tests or test infrastructure.**

```bash
cargo build --workspace
cargo test --workspace   # existing tests only; fix or delete ones your change obsoletes
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

All of these must be clean before pushing to `main`. Windows (MSVC) is the primary target; the server must also build on Linux.

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
- Tests: deferred. No new tests required; verify features by running them and say how in TASKS.md Notes.

## Git

- **Each agent works in its own git worktree, never in another agent's checkout or the user's.** Uncommitted edits in a shared folder get swept into the other agent's commits.

  | Who | Folder | Branch |
  |---|---|---|
  | Claude Code | `../tervano-claude` | `agent/claude` |
  | Codex | `../tervano-codex` | `agent/codex` |
  | User | `tervano/` (main checkout) | `main` |

  Create yours once from the main checkout: `git worktree add -b agent/<you> ../tervano-<you> origin/main`.
  Each worktree has its own `target/` (first build is a full build) and its own git-ignored `dev-data/`.
- Small commits with Conventional Commit subjects (`feat(server): …`, `fix(agent): …`, `chore(tasks): …`).
- **Sprints** (see TASKS.md "How to use"): lock tasks → work on your branch → merge to `main` at sprint end.
  - **Lock** (push immediately, alone). At sprint start your branch equals `origin/main`, so:
    `git fetch origin && git rebase origin/main`, edit only the TASKS.md rows, commit `chore(tasks): lock T-xxx`, `git push origin HEAD:main`.
    Locking more tasks mid-sprint (your branch has unmerged work), use a throwaway worktree so only the lock lands:
    `git worktree add --detach ../tervano-lock origin/main`, edit + commit TASKS.md there, `git push origin HEAD:main`, `git worktree remove ../tervano-lock`, then `git rebase origin/main` in your own worktree.
  - **Merge** at sprint end (and at least once per session): `git fetch origin && git rebase origin/main`; resolve conflicts (in TASKS.md keep both agents' rows; never change the other agent's locked rows); then `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` must pass; mark tasks `[x]` with verification notes; `git push origin HEAD:main`. If the push is rejected because the other agent merged first, repeat.
  - Never force-push `main`. Your `agent/*` branch is private and needn't be pushed.
- Stage files explicitly (`git add <paths>`), not `git add -A`.
- Update TASKS.md (status + verification note) in the same commit as the feature. Update README status table when a user-visible feature changes.
- Don't edit files under a crate where the other agent has an in-progress task without noting it in TASKS.md.

## Honesty rules (from PLAN)

- "Implemented" means working code + passing acceptance. Compiling is not evidence.
- Windows behaviour (sessions, service, capture, input) must be run on Windows before it's marked done. Record what OS it was tested on.
- Never fabricate test results, benchmarks, or competitor claims.
