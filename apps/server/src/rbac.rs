//! Technician roles and device scopes (T-806, PLAN §12.4).
//!
//! Roles are ordered: viewer (read devices, inventory, events, jobs) < operator (+ queue and cancel
//! jobs, edit groups) < admin (+ audit log, metrics, groups used as scopes). A scope limits a
//! technician to the devices in one or more groups (static, or search groups refreshed every minute); scoped technicians also only see their
//! own jobs and cannot edit groups. Out-of-scope devices answer 404, like unknown ones, so a scope
//! does not reveal which devices exist.

use super::*;

/// SQL condition on a `devices` row aliased with column `id`: the device is in a scope group of
/// technician `?`.
pub(crate) const IN_SCOPE: &str = "id IN (SELECT m.device_id FROM group_members m
    JOIN technician_scopes ts ON ts.group_id = m.group_id WHERE ts.technician = ?)";

pub(crate) fn parse_role(s: &str) -> TechRole {
    match s {
        "admin" => TechRole::Admin,
        "operator" => TechRole::Operator,
        // Unknown values fail closed.
        _ => TechRole::Viewer,
    }
}

pub(crate) fn role_str(r: TechRole) -> &'static str {
    match r {
        TechRole::Viewer => "viewer",
        TechRole::Operator => "operator",
        TechRole::Admin => "admin",
    }
}

impl TechAuth {
    /// Name to bind for [`IN_SCOPE`] filters; `None` when the technician sees every device.
    pub(crate) fn scope_name(&self) -> Option<&str> {
        self.scoped.then_some(self.name.as_str())
    }

    pub(crate) async fn deny(
        &self,
        s: &AppState,
        action: &str,
        target: &str,
        why: String,
    ) -> AppError {
        audit(
            &s.db,
            &format!("tech:{}", self.name),
            action,
            target,
            false,
            &why,
            None,
        )
        .await;
        AppError::new(err(StatusCode::FORBIDDEN, why))
    }

    /// Fails with 403 (audited) unless the technician has at least `min`.
    pub(crate) async fn require(
        &self,
        s: &AppState,
        min: TechRole,
        action: &str,
        target: &str,
    ) -> Result<(), AppError> {
        if self.role >= min {
            return Ok(());
        }
        Err(self
            .deny(
                s,
                action,
                target,
                format!(
                    "technician {} has the {} role; this needs {}",
                    self.name,
                    role_str(self.role),
                    role_str(min)
                ),
            )
            .await)
    }

    /// Group edits change what jobs and scopes reach, so scoped technicians cannot make them.
    pub(crate) async fn require_unscoped(
        &self,
        s: &AppState,
        action: &str,
        target: &str,
    ) -> Result<(), AppError> {
        if !self.scoped {
            return Ok(());
        }
        Err(self
            .deny(
                s,
                action,
                target,
                format!(
                    "technician {} is limited to a device scope and cannot do this",
                    self.name
                ),
            )
            .await)
    }

    pub(crate) async fn sees_device(&self, db: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
        if !self.scoped {
            return Ok(true);
        }
        sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND {IN_SCOPE})"
        ))
        .bind(id)
        .bind(&self.name)
        .fetch_one(db)
        .await
    }

    /// 404 for a device outside the technician's scope.
    pub(crate) async fn check_device(&self, db: &SqlitePool, id: Uuid) -> Result<(), AppError> {
        if self.sees_device(db, &id.to_string()).await? {
            Ok(())
        } else {
            Err(AppError::new(err(
                StatusCode::NOT_FOUND,
                "device not found",
            )))
        }
    }

    /// Admin, or an unscoped technician acting on a group nobody is scoped to.
    pub(crate) async fn may_edit_group(
        &self,
        s: &AppState,
        id: Option<Uuid>,
    ) -> Result<(), AppError> {
        let action = "group.write";
        let target = id.map(|i| i.to_string()).unwrap_or_default();
        self.require(s, TechRole::Operator, action, &target).await?;
        self.require_unscoped(s, action, &target).await?;
        if let Some(id) = id {
            let used: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM technician_scopes WHERE group_id = ?)",
            )
            .bind(id.to_string())
            .fetch_one(&s.db)
            .await?;
            if used {
                self.require(s, TechRole::Admin, action, &target).await?;
            }
        }
        Ok(())
    }
}

/// `GET /api/v1/me`: who the Console is signed in as, so it can hide what this technician cannot do.
pub(crate) async fn me(
    State(s): State<AppState>,
    tech: TechAuth,
) -> Result<Json<TechnicianInfo>, AppError> {
    let expires_at: i64 = sqlx::query_scalar("SELECT expires_at FROM technicians WHERE name = ?")
        .bind(&tech.name)
        .fetch_one(&s.db)
        .await?;
    let scope: Vec<String> = sqlx::query_scalar(
        "SELECT g.name FROM technician_scopes ts JOIN device_groups g ON g.id = ts.group_id
         WHERE ts.technician = ? ORDER BY g.name COLLATE NOCASE",
    )
    .bind(&tech.name)
    .fetch_all(&s.db)
    .await?;
    Ok(Json(TechnicianInfo {
        name: tech.name,
        role: tech.role,
        scope,
        expires_at,
    }))
}

/// CLI: set a technician's role and/or replace their scope (group names; empty = all devices).
pub async fn set_technician_access(
    db: &SqlitePool,
    name: &str,
    role: Option<TechRole>,
    scope: Option<&[String]>,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM technicians WHERE name = ?)")
            .bind(name)
            .fetch_one(&mut *tx)
            .await?;
    anyhow::ensure!(exists, "no technician named {name}");
    if let Some(role) = role {
        sqlx::query("UPDATE technicians SET role = ? WHERE name = ?")
            .bind(role_str(role))
            .bind(name)
            .execute(&mut *tx)
            .await?;
    }
    let mut query_groups = Vec::new();
    if let Some(groups) = scope {
        sqlx::query("DELETE FROM technician_scopes WHERE technician = ?")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        for g in groups {
            let row: Option<(String, String)> =
                sqlx::query_as("SELECT id, kind FROM device_groups WHERE name = ?")
                    .bind(g)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some((id, kind)) = row else {
                anyhow::bail!("no device group named {g:?}");
            };
            if kind == "query" {
                query_groups.push(id.clone());
            }
            sqlx::query(
                "INSERT OR IGNORE INTO technician_scopes (technician, group_id) VALUES (?, ?)",
            )
            .bind(name)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    // After the commit: the refresh writes through another connection. Makes a search-group scope
    // effective now rather than at the next minute's refresh.
    for id in &query_groups {
        crate::groups::refresh_query_groups(db, Some(id)).await?;
    }
    audit(
        db,
        actor,
        "technician.access",
        name,
        true,
        &format!(
            "role={:?} scope={:?}",
            role.map(role_str),
            scope.map(|s| s.join(","))
        ),
        None,
    )
    .await;
    Ok(())
}
