//! Shared application state injected into every Axum handler.
//!
//! [`AppState`] is constructed once at startup and cloned into each request
//! via Axum's [`axum::extract::State`] extractor. All fields are `Arc`-wrapped
//! so cloning is cheap.
//!
//! # Security note
//!
//! `tenant_id` is **never** stored here. It is extracted from the validated
//! JWT on every request and lives only in [`crate::middleware::AuthUser`].

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use jsonwebtoken::{DecodingKey, EncodingKey};
use kron_types::KronConfig;

/// JWT claims structure embedded in every KRON access token.
///
/// All fields map directly to registered (`sub`, `exp`, `iat`, `jti`) and
/// private (`tid`, `role`) JWT claims. The `jti` uniquely identifies the
/// token for revocation purposes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KronClaims {
    /// Subject: the user ID string.
    pub sub: String,
    /// Tenant ID this token is scoped to.
    pub tid: String,
    /// RBAC role name (e.g. `"admin"`, `"analyst"`).
    pub role: String,
    /// JWT ID — a UUID v4 used to revoke individual tokens.
    pub jti: String,
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
    /// Expiry timestamp (Unix seconds).
    pub exp: u64,
}

/// Service that issues and validates KRON JWTs using RS256.
///
/// Holds the encoding key (private) and decoding key (public). The private
/// key is only held in memory and never written to a response.
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Token validity window in seconds (from config).
    pub expiry_secs: u64,
}

impl JwtService {
    /// Creates a new `JwtService` from RSA PEM key bytes.
    ///
    /// # Arguments
    /// * `private_pem` - RSA private key in PEM format (PKCS#8 or traditional)
    /// * `public_pem`  - RSA public key in PEM format
    /// * `expiry_secs` - Token validity in seconds
    ///
    /// # Errors
    ///
    /// Returns an error string if either PEM is malformed.
    pub fn from_pem(
        private_pem: &[u8],
        public_pem: &[u8],
        expiry_secs: u64,
    ) -> Result<Self, String> {
        let encoding_key = EncodingKey::from_rsa_pem(private_pem)
            .map_err(|e| format!("invalid RSA private key: {e}"))?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem)
            .map_err(|e| format!("invalid RSA public key: {e}"))?;
        Ok(Self {
            encoding_key,
            decoding_key,
            expiry_secs,
        })
    }

    /// Issues a signed RS256 JWT for the given user.
    ///
    /// # Arguments
    /// * `user_id`   - Subject claim value
    /// * `tenant_id` - Tenant UUID string
    /// * `role`      - RBAC role string
    ///
    /// # Returns
    ///
    /// A signed JWT string and the `jti` UUID for revocation tracking.
    ///
    /// # Errors
    ///
    /// Returns an error string if JWT encoding fails.
    pub fn issue(
        &self,
        user_id: &str,
        tenant_id: &str,
        role: &str,
    ) -> Result<(String, String), String> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_secs();

        let jti = uuid::Uuid::new_v4().to_string();
        let claims = KronClaims {
            sub: user_id.to_owned(),
            tid: tenant_id.to_owned(),
            role: role.to_owned(),
            jti: jti.clone(),
            iat: now,
            exp: now + self.expiry_secs,
        };

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| format!("JWT encode error: {e}"))?;

        Ok((token, jti))
    }

    /// Validates a JWT and returns the embedded claims.
    ///
    /// Verifies the RS256 signature, `exp` claim, and required fields.
    ///
    /// # Errors
    ///
    /// Returns [`kron_auth::AuthError`] if the token is invalid, expired, or
    /// structurally malformed.
    pub fn validate(&self, token: &str) -> Result<KronClaims, kron_auth::AuthError> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = true;

        jsonwebtoken::decode::<KronClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    kron_auth::AuthError::TokenExpired
                }
                _ => kron_auth::AuthError::TokenInvalid(e.to_string()),
            })
    }

    /// Returns the RSA public key in JWK set format for `/.well-known/jwks.json`.
    ///
    /// # Errors
    ///
    /// Returns an error string if JWK conversion fails.
    pub fn public_jwks(&self) -> Result<serde_json::Value, String> {
        // The full JWK conversion requires the raw public key bytes. For now we
        // return a minimal structure indicating RS256 usage. A complete
        // implementation will extract `n` and `e` modulus/exponent fields.
        // TODO(#11, hardik, v1.1): Extract RSA n/e from DecodingKey for full JWK response
        Ok(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig"
            }]
        }))
    }
}

/// Tracks live WebSocket connections per tenant.
///
/// Used to enforce the `api.max_ws_connections_per_tenant` limit.
/// Values are `Arc<AtomicUsize>` so the connection handler can decrement
/// on drop without holding the map lock.
pub type WsConnCounts = Arc<dashmap::DashMap<String, Arc<AtomicUsize>>>;

/// Increments the WebSocket connection count for `tenant_id`.
///
/// Returns `Err(())` if the limit would be exceeded and the connection
/// should be rejected.
///
/// # Arguments
/// * `counts`     — the shared connection-count map from [`AppState`]
/// * `tenant_id`  — the tenant whose limit is being checked
/// * `max`        — maximum concurrent connections allowed per tenant
pub fn ws_conn_acquire(
    counts: &WsConnCounts,
    tenant_id: &str,
    max: usize,
) -> Result<Arc<AtomicUsize>, ()> {
    let counter = counts
        .entry(tenant_id.to_owned())
        .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
        .clone();

    // compare_exchange loop: increment only if current < max
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= max {
            return Err(());
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(counter),
            Err(actual) => current = actual,
        }
    }
}

/// Decrements the WebSocket connection count for the given counter.
///
/// Call this when a WebSocket connection closes.
pub fn ws_conn_release(counter: &AtomicUsize) {
    // Saturating sub guards against underflow in case of bugs.
    counter.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    }).ok();
}

/// Shared application state for all Axum handlers.
///
/// Constructed once at startup. All fields are `Arc`-backed so that
/// `AppState::clone()` is O(1) and safe across async tasks.
///
/// # Persistence
///
/// Authentication security state (revoked tokens, login attempt lockouts) is
/// now backed by [`kron_storage::AdaptiveStorage`] JSON stores so they survive
/// process restarts. Formerly in-memory only guards have been removed.
#[derive(Clone)]
pub struct AppState {
    /// Unified storage backend (ClickHouse or DuckDB depending on tier).
    /// Also holds `users`, `revoked_tokens`, `login_attempts`, and `assets` stores.
    pub storage: Arc<kron_storage::AdaptiveStorage>,
    /// Message bus producer for publishing events from API handlers.
    pub bus: Arc<dyn kron_bus::BusProducer>,
    /// JWT issuance and validation service.
    pub jwt: Arc<JwtService>,
    /// Full platform configuration.
    pub config: Arc<KronConfig>,
    /// Per-tenant WebSocket connection counts for limit enforcement.
    pub ws_conn_counts: WsConnCounts,
}
