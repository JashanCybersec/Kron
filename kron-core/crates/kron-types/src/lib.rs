//! `kron-types` — Shared types for the KRON SIEM platform.
//!
//! This crate is the foundation of the workspace. It contains all shared
//! data types, error enums, and configuration structs used by every other
//! `kron-*` crate. It has zero internal dependencies.
//!
//! # Module structure
//!
//! - [`ids`] — `TenantId`, `EventId`, `AlertId`, `RuleId` newtypes
//! - [`event`] — `KronEvent` canonical event schema
//! - [`alert`] — `KronAlert` struct
//! - [`enums`] — `Severity`, `EventSource`, `EventCategory`, `AssetCriticality`
//! - [`config`] — `KronConfig` full configuration tree
//! - [`error`] — `KronError` top-level error enum
//! - [`context`] — `TenantContext` request-scoped tenant holder

pub mod agent;
pub mod alert;
pub mod config;
pub mod context;
pub mod enums;
pub mod error;
pub mod event;
pub mod ids;

// Re-export the most commonly used types at the crate root.
pub use agent::{
    EventAck, EventBatch, HeartbeatRequest, HeartbeatResponse, RegisterRequest, RegisterResponse,
};
pub use alert::KronAlert;
pub use config::{
    ClickHouseConfig, DeploymentMode, DuckDbConfig, EmbeddedBusConfig, KronConfig, RedpandaConfig,
};
pub use context::TenantContext;
pub use enums::{
    AlertStatus, AssetCriticality, AuthResult, DetectionSource, EventCategory, EventSource,
    FileAction, NetworkDirection, Severity, UserType,
};
pub use error::KronError;
pub use event::KronEvent;
pub use ids::{AgentId, AlertId, EventId, RuleId, TenantId};
