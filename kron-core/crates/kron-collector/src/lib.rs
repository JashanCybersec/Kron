//! `kron-collector` library — event intake for the KRON SIEM platform.
//!
//! Exposes the collector service as a library so that `kron-nano` can
//! embed it in a single-binary deployment.  The `kron-collector` binary
//! remains the standalone Standard/Enterprise entrypoint.
//!
//! # Public surface
//!
//! - [`Collector`] — orchestrator struct; call `Collector::new()` then `Collector::run().await`.
//! - [`ShutdownHandle`] — broadcast-based shutdown signal; create with `ShutdownHandle::new()`.
//! - [`CollectorError`] — all collector failure modes.

pub mod codec;
pub mod collector;
pub mod error;
pub mod grpc;
pub mod http_intake;
pub mod metrics;
pub mod registry;
pub mod shutdown;
pub mod syslog;

pub use collector::Collector;
pub use error::CollectorError;
pub use shutdown::ShutdownHandle;
