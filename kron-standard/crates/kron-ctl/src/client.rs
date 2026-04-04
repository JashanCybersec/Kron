//! HTTP client for the `kron-collector` management API.
//!
//! Wraps [`reqwest`] with typed request/response structs for each collector
//! endpoint that `kron-ctl` needs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CtlError;

// ─── Response types ───────────────────────────────────────────────────────────

/// Response from `GET /health`.
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    /// "ok" when the collector is up.
    pub status: String,
}

/// Single agent entry from `GET /agents`.
#[derive(Debug, Deserialize, Serialize)]
pub struct AgentSummary {
    /// Stable agent UUID.
    pub agent_id: String,
    /// Tenant this agent belongs to.
    pub tenant_id: String,
    /// FQDN or short hostname.
    pub hostname: String,
    /// Agent binary version string.
    pub agent_version: String,
    /// UTC timestamp of the last heartbeat.
    pub last_heartbeat_at: DateTime<Utc>,
    /// True when the agent has exceeded the heartbeat timeout.
    pub is_dark: bool,
}

/// Request body for `POST /agents/register`.
#[derive(Debug, Serialize)]
pub struct AgentRegisterRequest {
    /// Hostname to pre-register.
    pub hostname: String,
    /// Optional tenant UUID; the collector uses its default if absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// Response from `POST /agents/register`.
#[derive(Debug, Deserialize)]
pub struct AgentRegisterResponse {
    /// Assigned agent identifier.
    pub agent_id: String,
    /// Assigned tenant identifier.
    pub tenant_id: String,
    /// UTC registration timestamp.
    pub registered_at: DateTime<Utc>,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// Thin typed wrapper around [`reqwest::Client`] for collector API calls.
pub struct CollectorClient {
    client: reqwest::Client,
    base_url: String,
}

impl CollectorClient {
    /// Create a new client targeting the given base URL (e.g. `http://localhost:9002`).
    ///
    /// # Errors
    /// Returns [`CtlError::Http`] if the underlying client cannot be built.
    pub fn new(base_url: String) -> Result<Self, CtlError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| CtlError::Http(format!("failed to build HTTP client: {e}")))?;

        Ok(Self { client, base_url })
    }

    /// `GET /health` — liveness probe.
    ///
    /// # Errors
    /// Returns [`CtlError::Http`] if the request fails or returns a non-200 status.
    pub async fn health(&self) -> Result<HealthResponse, CtlError> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CtlError::Http(format!("GET /health: {e}")))?;

        if !resp.status().is_success() {
            return Err(CtlError::Http(format!(
                "GET /health returned HTTP {}",
                resp.status()
            )));
        }

        resp.json::<HealthResponse>()
            .await
            .map_err(|e| CtlError::Http(format!("GET /health decode: {e}")))
    }

    /// `GET /agents` — list all registered agents.
    ///
    /// # Errors
    /// Returns [`CtlError::Http`] if the request fails or returns a non-200 status.
    pub async fn list_agents(&self) -> Result<Vec<AgentSummary>, CtlError> {
        let url = format!("{}/agents", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CtlError::Http(format!("GET /agents: {e}")))?;

        if !resp.status().is_success() {
            return Err(CtlError::Http(format!(
                "GET /agents returned HTTP {}",
                resp.status()
            )));
        }

        resp.json::<Vec<AgentSummary>>()
            .await
            .map_err(|e| CtlError::Http(format!("GET /agents decode: {e}")))
    }

    /// `POST /agents/register` — pre-register an agent and receive its ID.
    ///
    /// # Errors
    /// Returns [`CtlError::Http`] if the request fails or returns a non-200 status.
    pub async fn register_agent(
        &self,
        hostname: &str,
        tenant_id: Option<&str>,
    ) -> Result<AgentRegisterResponse, CtlError> {
        let url = format!("{}/agents/register", self.base_url);
        let body = AgentRegisterRequest {
            hostname: hostname.to_owned(),
            tenant_id: tenant_id.map(str::to_owned),
        };

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CtlError::Http(format!("POST /agents/register: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CtlError::Http(format!(
                "POST /agents/register returned HTTP {status}: {text}"
            )));
        }

        resp.json::<AgentRegisterResponse>()
            .await
            .map_err(|e| CtlError::Http(format!("POST /agents/register decode: {e}")))
    }
}
