//! Request-scoped tenant context.
//!
//! [`TenantContext`] is injected into every authenticated request handler
//! by JWT validation middleware. It is the **only** valid source of `tenant_id`
//! in application code. No handler, storage call, or bus operation may use a
//! `tenant_id` sourced from a request body or query parameter (ADR-007).

use crate::ids::TenantId;

/// The authenticated context for a single request within a tenant.
///
/// Created exclusively by JWT validation middleware. Application code must
/// never construct a `TenantContext` directly with an arbitrary `tenant_id`.
#[derive(Debug, Clone)]
pub struct TenantContext {
    tenant_id: TenantId,
    /// The authenticated user's ID within this tenant.
    pub user_id: String,
    /// The authenticated user's RBAC role (e.g. "admin", "analyst", "viewer").
    pub role: String,
}

impl TenantContext {
    /// Creates a new `TenantContext` from a validated JWT claim.
    ///
    /// This constructor must only be called from the JWT validation middleware.
    /// All other code receives `TenantContext` by reference, never constructs it.
    #[must_use]
    pub fn new(tenant_id: TenantId, user_id: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            tenant_id,
            user_id: user_id.into(),
            role: role.into(),
        }
    }

    /// Returns the tenant ID for this request.
    ///
    /// Pass this to every storage and bus operation that requires a `tenant_id`.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns `true` if the user has admin or MSSP-admin privileges.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        matches!(self.role.as_str(), "admin" | "mssp_admin")
    }

    /// Returns `true` if the user can perform write operations (modify data).
    #[must_use]
    pub fn can_write(&self) -> bool {
        matches!(
            self.role.as_str(),
            "analyst" | "responder" | "admin" | "mssp_admin"
        )
    }

    /// Returns `true` if the user can execute SOAR response actions.
    #[must_use]
    pub fn can_respond(&self) -> bool {
        matches!(self.role.as_str(), "responder" | "admin" | "mssp_admin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_context_when_checked_then_is_admin_and_can_write() {
        let ctx = TenantContext::new(TenantId::new(), "user1", "admin");
        assert!(ctx.is_admin());
        assert!(ctx.can_write());
        assert!(ctx.can_respond());
    }

    #[test]
    fn test_viewer_context_when_checked_then_cannot_write() {
        let ctx = TenantContext::new(TenantId::new(), "user2", "viewer");
        assert!(!ctx.is_admin());
        assert!(!ctx.can_write());
        assert!(!ctx.can_respond());
    }

    #[test]
    fn test_analyst_context_when_checked_then_can_write_but_not_respond() {
        let ctx = TenantContext::new(TenantId::new(), "user3", "analyst");
        assert!(!ctx.is_admin());
        assert!(ctx.can_write());
        assert!(!ctx.can_respond());
    }

    #[test]
    fn test_responder_context_when_checked_then_can_respond() {
        let ctx = TenantContext::new(TenantId::new(), "user4", "responder");
        assert!(!ctx.is_admin());
        assert!(ctx.can_write());
        assert!(ctx.can_respond());
    }

    #[test]
    fn test_tenant_id_when_accessed_then_matches_original() {
        let tenant_id = TenantId::new();
        let ctx = TenantContext::new(tenant_id, "user5", "analyst");
        assert_eq!(ctx.tenant_id(), tenant_id);
    }

    #[test]
    fn test_mssp_admin_context_when_checked_then_is_admin() {
        let ctx = TenantContext::new(TenantId::new(), "mssp1", "mssp_admin");
        assert!(ctx.is_admin());
        assert!(ctx.can_write());
        assert!(ctx.can_respond());
    }
}
