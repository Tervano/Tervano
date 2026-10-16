//! Device groups (T-801): named targets for searches and jobs. Static groups hold explicit
//! members; query groups store a device search that is re-run each time the group is listed.
//! Members are read through `GET /api/v1/devices?group=<id>` so every view gets the same summary.

use super::*;
use std::collections::BTreeSet;

const MAX_NAME_CHARS: usize = 80;
const MAX_QUERY_CHARS: usize = 200;
const MAX_GROUPS: i64 = 500;
const MAX_STATIC_MEMBERS: i64 = 10_000;
/// Per request, so one call stays within the body limit and a reasonable transaction.
const MAX_CHANGE: usize = 1000;

fn bad(msg: impl Into<String>) -> AppError {
    AppError::new(err(StatusCode::BAD_REQUEST, msg))
}

fn not_found() -> AppError {
    AppError::new(err(StatusCode::NOT_FOUND, "group not found"))
}

/// Kind and stored query of a group, for the device search.
pub(crate) async fn lookup(
    db: &SqlitePool,
    id: Uuid,
) -> Result<(GroupKind, Option<String>), AppError> {
    let row = sqlx::query("SELECT kind, query FROM device_groups WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(db)
        .await?
        .ok_or_else(not_found)?;
    let kind = match row.get::<&str, _>("kind") {
        "query" => GroupKind::Query,
        _ => GroupKind::Static,
    };
    Ok((kind, row.get("query")))
}

/// Groups, or the one with id `only`; a scoped technician (`scope`) sees only their scope groups.
async fn load(
    db: &SqlitePool,
    only: Option<Uuid>,
    scope: Option<&str>,
) -> Result<Vec<DeviceGroup>, AppError> {
    let rows = sqlx::query(
        "SELECT g.id, g.name, g.kind, g.query, g.created_by, g.created_at,
                (SELECT COUNT(*) FROM group_members m JOIN devices d ON d.id = m.device_id
                 WHERE m.group_id = g.id AND d.revoked = 0) AS members
         FROM device_groups g
         WHERE (?1 IS NULL OR g.id = ?1)
           AND (?2 IS NULL OR g.id IN (SELECT group_id FROM technician_scopes WHERE technician = ?2))
         ORDER BY g.name COLLATE NOCASE",
    )
    .bind(only.map(|id| id.to_string()))
    .bind(scope)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            let kind = if r.get::<&str, _>("kind") == "query" {
                GroupKind::Query
            } else {
                GroupKind::Static
            };
            Ok(DeviceGroup {
                id: r.get::<&str, _>("id").parse().map_err(|_| {
                    AppError::new(err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt group"))
                })?,
                name: r.get("name"),
                kind,
                query: r.get("query"),
                created_by: r.get("created_by"),
                created_at: r.get("created_at"),
                // A query group's size depends on the moment it is evaluated.
                members: (kind == GroupKind::Static).then(|| r.get::<i64, _>("members") as u32),
            })
        })
        .collect()
}

pub(crate) async fn list_groups(
    State(s): State<AppState>,
    tech: TechAuth,
) -> Result<Json<Vec<DeviceGroup>>, AppError> {
    Ok(Json(load(&s.db, None, tech.scope_name()).await?))
}

/// Counts the ids that are enrolled, non-revoked devices.
async fn known_devices(
    tx: &mut sqlx::SqliteConnection,
    ids: &BTreeSet<Uuid>,
) -> Result<usize, sqlx::Error> {
    let mut known = 0;
    for d in ids {
        let ok: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND revoked = 0)")
                .bind(d.to_string())
                .fetch_one(&mut *tx)
                .await?;
        known += usize::from(ok);
    }
    Ok(known)
}

pub(crate) async fn create_group(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(req): Json<GroupCreate>,
) -> Result<Json<DeviceGroup>, AppError> {
    tech.may_edit_group(&s, None).await?;
    let name = req.name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(bad(format!(
            "group name must be 1 to {MAX_NAME_CHARS} printable characters"
        )));
    }
    let devices: BTreeSet<Uuid> = req.devices.iter().copied().collect();
    let query = match req.kind {
        GroupKind::Query => {
            let q = req.query.as_deref().unwrap_or("").trim();
            if q.is_empty() || q.chars().count() > MAX_QUERY_CHARS || !devices.is_empty() {
                return Err(bad(format!(
                    "a query group needs a search of 1 to {MAX_QUERY_CHARS} characters and no device list"
                )));
            }
            Some(q.to_owned())
        }
        GroupKind::Static => {
            if req.query.is_some() || devices.len() > MAX_CHANGE {
                return Err(bad(format!(
                    "a static group takes up to {MAX_CHANGE} devices and no query"
                )));
            }
            None
        }
    };
    let mut tx = s.db.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_groups")
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_GROUPS {
        return Err(bad(format!("at most {MAX_GROUPS} groups")));
    }
    if known_devices(&mut tx, &devices).await? != devices.len() {
        return Err(bad("some selected devices are unknown or revoked"));
    }
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO device_groups (id, name, kind, query, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO NOTHING",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(match req.kind {
        GroupKind::Static => "static",
        GroupKind::Query => "query",
    })
    .bind(&query)
    .bind(&tech.name)
    .bind(now_millis())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(AppError::new(err(
            StatusCode::CONFLICT,
            format!("a group named {name:?} already exists"),
        )));
    }
    for d in &devices {
        sqlx::query("INSERT INTO group_members (group_id, device_id) VALUES (?, ?)")
            .bind(id.to_string())
            .bind(d.to_string())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "group.create",
        &id.to_string(),
        true,
        &format!(
            "name={name:?} kind={:?} query={query:?} members={}",
            req.kind,
            devices.len()
        ),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    load(&s.db, Some(id), None)
        .await?
        .pop()
        .map(Json)
        .ok_or_else(not_found)
}

pub(crate) async fn change_members(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
    Json(req): Json<GroupMembers>,
) -> Result<Json<DeviceGroup>, AppError> {
    tech.may_edit_group(&s, Some(id)).await?;
    let add: BTreeSet<Uuid> = req.add.iter().copied().collect();
    let remove: BTreeSet<Uuid> = req.remove.iter().copied().collect();
    if add.len() + remove.len() > MAX_CHANGE {
        return Err(bad(format!("at most {MAX_CHANGE} changes per request")));
    }
    if lookup(&s.db, id).await?.0 != GroupKind::Static {
        return Err(bad(
            "members of a query group come from its search; edit the search instead",
        ));
    }
    let mut tx = s.db.begin().await?;
    if known_devices(&mut tx, &add).await? != add.len() {
        return Err(bad("some devices to add are unknown or revoked"));
    }
    let gid = id.to_string();
    for d in &add {
        sqlx::query("INSERT OR IGNORE INTO group_members (group_id, device_id) VALUES (?, ?)")
            .bind(&gid)
            .bind(d.to_string())
            .execute(&mut *tx)
            .await?;
    }
    for d in &remove {
        sqlx::query("DELETE FROM group_members WHERE group_id = ? AND device_id = ?")
            .bind(&gid)
            .bind(d.to_string())
            .execute(&mut *tx)
            .await?;
    }
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = ?")
        .bind(&gid)
        .fetch_one(&mut *tx)
        .await?;
    if total > MAX_STATIC_MEMBERS {
        return Err(bad(format!(
            "a static group holds at most {MAX_STATIC_MEMBERS} devices"
        )));
    }
    tx.commit().await?;
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "group.members",
        &gid,
        true,
        &format!("added={} removed={}", add.len(), remove.len()),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    load(&s.db, Some(id), None)
        .await?
        .pop()
        .map(Json)
        .ok_or_else(not_found)
}

pub(crate) async fn delete_group(
    State(s): State<AppState>,
    tech: TechAuth,
    client: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    tech.may_edit_group(&s, Some(id)).await?;
    let scoped: Vec<String> =
        sqlx::query_scalar("SELECT technician FROM technician_scopes WHERE group_id = ?")
            .bind(id.to_string())
            .fetch_all(&s.db)
            .await?;
    if !scoped.is_empty() {
        return Err(AppError::new(err(
            StatusCode::CONFLICT,
            format!(
                "this group is the device scope of {}; change their scope first",
                scoped.join(", ")
            ),
        )));
    }
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM device_groups WHERE id = ? RETURNING name")
            .bind(id.to_string())
            .fetch_optional(&s.db)
            .await?;
    let name = name.ok_or_else(not_found)?;
    audit(
        &s.db,
        &format!("tech:{}", tech.name),
        "group.delete",
        &id.to_string(),
        true,
        &format!("name={name:?}"),
        client.map(|c| c.0.0.ip()),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
