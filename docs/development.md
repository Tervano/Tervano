# Development workflow

Requirements are in [PLAN.md](../PLAN.md); the live task board is
[TASKS.md](../TASKS.md). Read its **How to use** section and
[AGENTS.md](../AGENTS.md) before work. Each contributor uses their own
worktree. Lock tasks with a TASKS.md-only commit pushed to `main` before code,
keep implementation on an agent branch, and merge at the end of each sprint.
Do not edit another agent's locked task or checkout.

The workspace uses Rust 2024, stable, and a committed Cargo.lock. Add code to
an existing app/crate unless two apps need shared non-wire code; shared network
types belong in `crates/protocol` and version changes follow its header rules.
The [ADRs](adr/0001-iced-console.md) explain the current Iced, SQLite, and
HTTP+JSON choices.

```bash
cargo fmt --all
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run these before pushing to `main`; the Server must also build on Linux. New
tests and test infrastructure are deferred under PLAN.md, but existing tests
must keep passing. Verify changed behavior by running it on the target OS and
record exactly what was observed in TASKS.md. Use `dev-data/` for scratch
configs/databases; it is git-ignored. Never commit tokens, private keys, or
real user data.

The [README quick start](../README.md#quick-start-development) walks through
Agent → Server → Console locally. For Server behavior, you can use a scratch
SQLite database and loopback listener; for Windows Agent/direct behavior, run
on Windows. Keep the [README feature table](../README.md#feature-status) and
[security model](security-model.md) current when behavior changes.
