# ADR-0002: SQLite first, PostgreSQL for larger deployments

- Status: Accepted for Phase 1 (recorded 2026-10-15)
- Scope: `apps/server`

## Context

The initial vertical slice needs persistent enrollment, device projections, and search with a low-friction local setup. [PLAN.md](../../PLAN.md) §3 prefers PostgreSQL for centralized deployments and permits SQLite as a lightweight database. The Server currently has SQLx SQLite migrations and a single `SqlitePool`.

## Decision

Ship Phase 1 with SQLite. Keep database access inside the Server and use migrations for schema changes. Add PostgreSQL as a separately verified backend in T-111; do not promise that today's SQLite migrations or SQL queries run unchanged on PostgreSQL.

## Consequences

- A local Server needs no external database service, which makes the Agent → Server → Console path easy to run and inspect.
- SQLite is a single-file operational dependency. Backup, write contention, high availability, and large-fleet performance need explicit deployment work and measurement (T-952, T-112).
- Storage choices stay out of `crates/protocol`. Backend compatibility work belongs with the PostgreSQL implementation, rather than a speculative abstraction now.
