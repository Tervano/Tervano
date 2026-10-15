# Contributing to Tervano

Tervano is in early development. Start with [PLAN.md](PLAN.md) for requirements,
[AGENTS.md](AGENTS.md) for code and Git conventions, and the **How to use** section
of [TASKS.md](TASKS.md) before changing code. Claim an unlocked task first and
respect other contributors' locks and worktrees.

## Make a change

1. Work in your own checkout or worktree using the sprint workflow in AGENTS.md.
2. Keep the change within the claimed task. Update TASKS.md with the actual
   verification method and update the README feature table for user-visible work.
3. Use Rust 2024 on stable. Prefer existing dependencies; explain any new one in
   the commit message and commit Cargo.lock when it changes.
4. Run `cargo fmt --all`, `cargo build --workspace`,
   `cargo test --workspace` (existing tests), and
   `cargo clippy --workspace --all-targets -- -D warnings` before merging.
   The Server must also build on Linux. Record the OS used for manual checks.
5. Use Conventional Commit subjects, such as `fix(server): reject stale events`.

Testing is deferred under PLAN.md: do not add new tests or test infrastructure
until that decision changes. Demonstrate working behavior manually where the task
requires it. A clean build alone does not establish that a feature works.

## Security and conduct

Do not commit credentials, enrollment tokens, device secrets, private keys, or
real user data. Report security issues through [SECURITY.md](SECURITY.md) and
follow the [Code of Conduct](CODE_OF_CONDUCT.md). The generated Cargo dependency
inventory is [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md); regenerate it
with `python scripts/generate-third-party-licenses.py` after changing dependencies.
