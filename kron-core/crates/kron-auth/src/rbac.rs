//! Role-Based Access Control (RBAC) for the KRON SIEM platform.
//!
//! Exposes the [`can`] function which answers whether a [`Role`] may perform
//! an [`Action`] on a [`Resource`]. The function is a pure compile-time
//! decision tree — no I/O, no allocations, deterministic.
//!
//! # Matrix summary
//!
//! | Role        | Events | Alerts     | Rules      | Assets     | Playbooks | Users | Settings | Compliance | Agents |
//! |-------------|--------|------------|------------|------------|-----------|-------|----------|------------|--------|
//! | SuperAdmin  | all    | all        | all        | all        | all       | all   | all      | all        | all    |
//! | Admin       | all    | all        | all        | all        | all       | R+W   | R+W+E    | all        | all    |
//! | Analyst     | R      | R+W        | R+W        | R+W        | Execute   | —     | —        | R          | R      |
//! | Viewer      | R      | R          | R          | R          | R         | —     | R        | R          | R      |
//! | ApiKey      | R      | R          | —          | —          | —         | —     | —        | —          | —      |

use std::fmt;

use serde::{Deserialize, Serialize};

/// Caller roles within the KRON platform.
///
/// Roles are embedded in JWT claims and drive all authorization decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full platform access including user management and global settings.
    SuperAdmin,
    /// Tenant-scoped administrative access; cannot delete users or manage settings.
    Admin,
    /// Day-to-day SOC analyst; read/write on detections, limited on admin.
    Analyst,
    /// Read-only access to all non-admin resources.
    Viewer,
    /// Machine-to-machine API key; read access to events and alerts only.
    ApiKey,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SuperAdmin => write!(f, "super_admin"),
            Self::Admin => write!(f, "admin"),
            Self::Analyst => write!(f, "analyst"),
            Self::Viewer => write!(f, "viewer"),
            Self::ApiKey => write!(f, "api_key"),
        }
    }
}

/// Actions that may be performed on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Query or list resources.
    Read,
    /// Create or update resources.
    Write,
    /// Permanently remove resources.
    Delete,
    /// Trigger execution (e.g. run a playbook).
    Execute,
    /// Administrative management of the resource type itself.
    Manage,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Delete => write!(f, "delete"),
            Self::Execute => write!(f, "execute"),
            Self::Manage => write!(f, "manage"),
        }
    }
}

/// Resources that actions can be performed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// Normalised telemetry events stored in `ClickHouse` / `DuckDB`.
    Events,
    /// Generated alerts and their status.
    Alerts,
    /// SIGMA detection rules.
    Rules,
    /// Asset inventory records.
    Assets,
    /// SOAR playbook definitions and execution history.
    Playbooks,
    /// Platform user accounts (within tenant).
    Users,
    /// Tenant-level platform settings.
    Settings,
    /// Compliance frameworks and generated reports.
    Compliance,
    /// Collection agents registered to the tenant.
    Agents,
    /// Tenant records (MSSP portal — super_admin only for write).
    Tenants,
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Events => write!(f, "events"),
            Self::Alerts => write!(f, "alerts"),
            Self::Rules => write!(f, "rules"),
            Self::Assets => write!(f, "assets"),
            Self::Playbooks => write!(f, "playbooks"),
            Self::Users => write!(f, "users"),
            Self::Settings => write!(f, "settings"),
            Self::Compliance => write!(f, "compliance"),
            Self::Agents => write!(f, "agents"),
            Self::Tenants => write!(f, "tenants"),
        }
    }
}

/// Returns whether `role` is permitted to perform `action` on `resource`.
///
/// This is a pure function with no I/O, no allocations, and deterministic
/// output. It is called on every authenticated request that touches a
/// protected resource.
///
/// # Arguments
/// * `role`     — the caller's role, as extracted from the verified JWT claim
/// * `action`   — the operation being attempted
/// * `resource` — the resource being targeted
///
/// # Returns
/// `true` if the action is permitted; `false` if it must be denied.
#[must_use]
pub fn can(role: Role, action: Action, resource: Resource) -> bool {
    match role {
        // SuperAdmin may do anything.
        Role::SuperAdmin => true,

        // Admin can do everything EXCEPT:
        //   - Users.Delete  (cannot delete user accounts)
        //   - Settings.Manage (cannot change platform-level settings management)
        //   - Tenants.Write/Delete/Manage (super_admin only for tenant lifecycle)
        Role::Admin => !matches!(
            (action, resource),
            (Action::Delete, Resource::Users)
                | (Action::Manage, Resource::Settings)
                | (
                    Action::Write | Action::Delete | Action::Manage,
                    Resource::Tenants
                )
        ),

        // Analyst: Events(R), Alerts(R+W), Rules(R+W), Assets(R+W),
        //          Playbooks(Execute), Compliance(R), Agents(R).
        Role::Analyst => matches!(
            (action, resource),
            (
                Action::Read,
                Resource::Events | Resource::Playbooks | Resource::Compliance | Resource::Agents,
            ) | (
                Action::Read | Action::Write,
                Resource::Alerts | Resource::Rules | Resource::Assets,
            ) | (Action::Execute, Resource::Playbooks)
        ),

        // Viewer: Read-only on all non-admin resources (no Users, no Settings.Write+).
        Role::Viewer => matches!(
            (action, resource),
            (
                Action::Read,
                Resource::Events
                    | Resource::Alerts
                    | Resource::Rules
                    | Resource::Assets
                    | Resource::Playbooks
                    | Resource::Settings
                    | Resource::Compliance
                    | Resource::Agents,
            )
        ),
        // ApiKey: Events(R), Alerts(R) only.
        Role::ApiKey => matches!(
            (action, resource),
            (Action::Read, Resource::Events | Resource::Alerts)
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_super_admin_when_any_action_then_always_permitted() {
        assert!(can(Role::SuperAdmin, Action::Delete, Resource::Users));
        assert!(can(Role::SuperAdmin, Action::Manage, Resource::Settings));
        assert!(can(Role::SuperAdmin, Action::Execute, Resource::Playbooks));
    }

    #[test]
    fn test_admin_when_delete_users_then_denied() {
        assert!(!can(Role::Admin, Action::Delete, Resource::Users));
    }

    #[test]
    fn test_admin_when_manage_settings_then_denied() {
        assert!(!can(Role::Admin, Action::Manage, Resource::Settings));
    }

    #[test]
    fn test_admin_when_write_alerts_then_permitted() {
        assert!(can(Role::Admin, Action::Write, Resource::Alerts));
    }

    #[test]
    fn test_analyst_when_read_events_then_permitted() {
        assert!(can(Role::Analyst, Action::Read, Resource::Events));
    }

    #[test]
    fn test_analyst_when_write_events_then_denied() {
        assert!(!can(Role::Analyst, Action::Write, Resource::Events));
    }

    #[test]
    fn test_analyst_when_execute_playbook_then_permitted() {
        assert!(can(Role::Analyst, Action::Execute, Resource::Playbooks));
    }

    #[test]
    fn test_analyst_when_manage_users_then_denied() {
        assert!(!can(Role::Analyst, Action::Manage, Resource::Users));
    }

    #[test]
    fn test_viewer_when_read_any_resource_then_permitted() {
        for resource in [
            Resource::Events,
            Resource::Alerts,
            Resource::Rules,
            Resource::Assets,
            Resource::Playbooks,
            Resource::Settings,
            Resource::Compliance,
            Resource::Agents,
        ] {
            assert!(
                can(Role::Viewer, Action::Read, resource),
                "{resource} should be readable"
            );
        }
    }

    #[test]
    fn test_viewer_when_write_then_denied() {
        assert!(!can(Role::Viewer, Action::Write, Resource::Alerts));
        assert!(!can(Role::Viewer, Action::Delete, Resource::Rules));
    }

    #[test]
    fn test_viewer_when_read_users_then_denied() {
        assert!(!can(Role::Viewer, Action::Read, Resource::Users));
    }

    #[test]
    fn test_api_key_when_read_events_and_alerts_then_permitted() {
        assert!(can(Role::ApiKey, Action::Read, Resource::Events));
        assert!(can(Role::ApiKey, Action::Read, Resource::Alerts));
    }

    #[test]
    fn test_api_key_when_read_rules_then_denied() {
        assert!(!can(Role::ApiKey, Action::Read, Resource::Rules));
    }

    #[test]
    fn test_api_key_when_write_events_then_denied() {
        assert!(!can(Role::ApiKey, Action::Write, Resource::Events));
    }
}
