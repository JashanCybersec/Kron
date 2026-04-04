//! Notification channels for the alert engine.
//!
//! Notifications follow a fallback chain: `WhatsApp` → SMS → Email.
//! P1/P2 (Critical/High) alerts bypass rate limiting and are always dispatched
//! immediately.  P3+ alerts are subject to a per-tenant, per-channel hourly
//! rate limit (default: 10/hour on `WhatsApp`).

pub mod dispatcher;
pub mod email;
pub mod rate_limit;
pub mod sms;
pub mod whatsapp;
