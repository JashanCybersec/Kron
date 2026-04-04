# KRON — AI & ML Implementation Guide

**Version:** 1.0

---

## AI Architecture Overview

KRON uses a two-tier AI architecture optimized for on-premise deployment without requiring internet connectivity or GPU hardware:

```
┌─────────────────────────────────────────────────────────────────┐
│  FAST PATH (every event, real-time)                              │
│  ONNX Runtime — CPU inference — <5ms per event                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────┐ ┌───────────┐  │
│  │ Isolation    │ │  XGBoost     │ │ Beaconing│ │   Exfil   │  │
│  │ Forest       │ │  UEBA        │ │ Detector │ │  Scorer   │  │
│  └──────────────┘ └──────────────┘ └──────────┘ └───────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  REASONING PATH (per alert, non-real-time)                       │
│  Mistral 7B — CPU (Standard) or GPU (Enterprise)                │
│  ┌──────────────────┐ ┌────────────────┐ ┌──────────────────┐  │
│  │ Alert narrative  │ │  NL→SQL query  │ │ Playbook         │  │
│  │ generation       │ │  translation   │ │ generation       │  │
│  └──────────────────┘ └────────────────┘ └──────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  LANGUAGE PATH (alert summaries — all tiers)                     │
│  Fine-tuned ONNX seq2seq — 8MB — <10ms                          │
│  └─ Hindi, Tamil, Telugu, Marathi, Bengali, Gujarati summaries  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ONNX Models

### Model 1: Isolation Forest (Anomaly Scorer)

**Purpose:** Detect unusual behaviour for any entity that doesn't fit a known attack pattern.

**Training data:**
- 30 days of baseline events per entity (user, host, IP)
- Features computed at event time

**Input features (normalized 0–1):**
```rust
pub struct AnomalyFeatures {
    hour_of_day: f32,           // 0.0-1.0 (hour / 24)
    day_of_week: f32,           // 0.0-1.0 (day / 7)
    failed_auth_rate_1h: f32,   // failed / total auths in 1h
    unique_dest_ips_1h: f32,    // log(count) / log(max_observed)
    bytes_out_1h: f32,          // log(bytes) / log(max_observed)
    process_spawn_rate_1h: f32, // processes/min / baseline_avg
    unique_files_accessed_1h: f32,
    is_privileged_user: f32,    // 0.0 or 1.0
    asset_criticality: f32,     // 0.0-1.0
    geo_novelty: f32,           // 1.0 if new country, else 0.0
}
```

**Output:** `anomaly_score: f32` (0.0 = normal, 1.0 = highly anomalous)

**Threshold for flagging:** 0.75 (contributes to alert risk score)

**Training:** scikit-learn IsolationForest → ONNX export via `sklearn-onnx`
```python
from sklearn.ensemble import IsolationForest
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

clf = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
clf.fit(X_train)

initial_type = [('input', FloatTensorType([None, 10]))]
onnx_model = convert_sklearn(clf, initial_types=initial_type)
with open("models/anomaly_scorer.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
```

---

### Model 2: XGBoost UEBA Classifier

**Purpose:** Classify whether a specific event represents anomalous user behaviour based on the user's 30-day personal baseline.

**Input features:**
```rust
pub struct UEBAFeatures {
    login_hour_deviation: f32,      // std devs from user's typical hour
    geo_distance_km: f32,           // distance from typical locations
    device_novelty: f32,            // 1.0 if new device fingerprint
    data_volume_deviation: f32,     // std devs from daily average
    concurrent_sessions: f32,       // simultaneous sessions (normalized)
    after_hours_flag: f32,          // 1.0 if outside working hours
    weekend_flag: f32,
    vpn_flag: f32,
    mfa_bypass_attempt: f32,
    days_since_last_login: f32,
}
```

**Output:** `ueba_anomaly_probability: f32` (0.0–1.0)

**Training:** XGBoost → ONNX via `onnxmltools`
```python
import xgboost as xgb
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

model = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05)
model.fit(X_train, y_train)

onnx_model = convert_xgboost(model, initial_types=[('input', FloatTensorType([None, 10]))])
with open("models/ueba_classifier.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
```

---

### Model 3: Beaconing Detector (FFT-based)

**Purpose:** Detect C2 beaconing — periodic connections at regular intervals.

**Algorithm:**
1. Collect timestamps of connections from src→dst pair over sliding 1-hour window
2. Convert to inter-arrival time series
3. Compute FFT on inter-arrival times
4. Dominant frequency peak strength = beaconing score

**Input:** `Vec<f32>` of inter-arrival times in seconds (max 3600 values)

**Output:** `beacon_score: f32` (0.0–1.0)

**Threshold:** 0.7 → classified as C2 beacon candidate

**Implementation (Rust):**
```rust
pub fn compute_beacon_score(inter_arrival_times: &[f32]) -> f32 {
    if inter_arrival_times.len() < 10 {
        return 0.0;
    }
    
    // Run through ONNX model (wraps FFT + peak detection)
    let session = BEACON_MODEL.get().unwrap();
    let input = ndarray::Array1::from(inter_arrival_times.to_vec())
        .into_shape((1, inter_arrival_times.len()))
        .unwrap();
    
    let outputs = session.run(ort::inputs!["input" => input].unwrap()).unwrap();
    outputs["beacon_score"].try_extract_scalar::<f32>().unwrap()
}
```

---

### Model 4: Exfil Volume Scorer

**Purpose:** Detect data exfiltration based on unusual outbound data volumes.

**Input features:**
```rust
pub struct ExfilFeatures {
    bytes_out_current_hour: f32,     // log-normalized
    bytes_out_baseline_avg: f32,     // 30-day hourly average
    bytes_out_baseline_std: f32,     // 30-day standard deviation
    upload_download_ratio: f32,      // bytes_out / bytes_in
    unique_dest_ips: f32,            // count of distinct destinations
    port_entropy: f32,               // entropy of destination ports
    time_concentration: f32,         // how concentrated in time
    after_hours_volume: f32,         // fraction occurring after hours
}
```

**Output:** `exfil_probability: f32` (0.0–1.0)

---

### Model 5: Multilingual Alert Summarizer

**Purpose:** Generate plain-language alert summaries in Indian languages.

**Architecture:** Fine-tuned T5-small (60M params) → ONNX export → 8MB quantized model

**Input:** Structured alert JSON serialized as template string
```
ALERT: {event_type} on {hostname} by {username} at {time}.
DETAILS: {key_indicators}.
CONTEXT: {user_baseline_deviation}.
```

**Output:** 2–3 sentence natural language summary

**Training data:**
- 50,000 structured alert → summary pairs
- Hindi: translated by security-domain translators, not general translation
- Model fine-tuned on Indian security vocabulary, Indian org names, Indian IP ranges

**Languages:** English (v1), Hindi (v1), Tamil/Telugu/Marathi (v1.5)

---

## Mistral 7B Integration

### When Mistral is Used
Mistral is the reasoning model — used for tasks requiring language understanding, not speed:

| Task | Mistral prompt | Response time |
|---|---|---|
| Alert narrative | Full alert context → 2-paragraph summary | 2–8s (CPU), <500ms (GPU) |
| NL query → SQL | User query + schema → ClickHouse SQL | 1–3s |
| Playbook generation | Alert type + asset info → SOAR playbook JSON | 3–10s |
| Root cause analysis | Event chain + alert → causal explanation | 4–12s |

### System Prompt
```
You are KRON, an Indian cybersecurity AI assistant. You help security analysts understand alerts and respond to incidents.

Rules:
- Never hallucinate IP addresses, usernames, or technical details not present in the provided data
- When generating SQL, only use tables and columns from the provided schema
- When generating playbooks, only use action types from the provided action library
- Respond in the language specified in the request
- Be concise — security analysts are busy
- Do not suggest contacting external services or sending data outside the organization
```

### NL Query Translation Prompt
```
Schema:
{clickhouse_schema}

User query (in {language}): {user_query}

Generate a ClickHouse SQL query that answers this question.
Requirements:
- Always include WHERE tenant_id = '{tenant_id}'
- Use only tables and columns in the schema above
- For time ranges, use the ts column with DateTime64 functions
- Return only the SQL query, no explanation
- Limit results to 1000 rows unless user specifies otherwise
```

### Alert Narrative Prompt
```
Generate a plain-language security alert summary for a non-expert.

Alert data:
{alert_json}

User context:
{user_baseline_summary}

Asset context:
{asset_details}

Requirements:
- Write in {language}
- Maximum 3 sentences
- Explain what happened, why it's suspicious, and what the risk is
- Do not use technical jargon
- Do not mention MITRE ATT&CK codes
- End with a clear recommendation (block/investigate/ignore)
```

### CPU Inference Setup (Standard tier)
```rust
// Using llama.cpp via llama-cpp-rs crate
use llama_cpp::{LlamaModel, LlamaParams, SessionParams};

pub fn load_mistral_cpu() -> LlamaModel {
    LlamaModel::load_from_file(
        "/var/lib/kron/models/mistral-7b-instruct-q4_k_m.gguf",
        LlamaParams {
            n_gpu_layers: 0,  // CPU only
            n_threads: num_cpus::get() as i32,
            ..Default::default()
        }
    ).expect("Failed to load Mistral model")
}
```

### GPU Inference Setup (Enterprise tier)
```rust
// Using candle crate with CUDA backend
use candle_core::{Device, DType};
use candle_transformers::models::mistral::Model;

pub fn load_mistral_gpu() -> Model {
    let device = Device::new_cuda(0).expect("No CUDA device");
    // Load full precision model
    Model::load(
        "/var/lib/kron/models/mistral-7b-instruct/",
        DType::F16,
        &device
    ).expect("Failed to load Mistral GPU model")
}
```

---

## UEBA Baseline System

### Baseline Computation
Baselines updated daily via ClickHouse materialized view + scheduled batch job.

```sql
-- Daily UEBA baseline update (runs as ClickHouse scheduled job)
INSERT INTO users (username, tenant_id, 
    typical_login_hours, typical_login_geos,
    typical_daily_events, typical_data_volume_mb, last_risk_update)
SELECT
    user_name,
    tenant_id,
    groupArray(toHour(ts)) AS typical_login_hours,
    groupArray(src_country)  AS typical_login_geos,
    count() / 30             AS typical_daily_events,
    sum(bytes_out) / 1048576 / 30 AS typical_data_volume_mb,
    now()
FROM events
WHERE
    ts >= now() - INTERVAL 30 DAY
    AND user_name != ''
    AND event_category = 'authentication'
    AND auth_result = 'success'
GROUP BY user_name, tenant_id;
```

### Anomaly Detection at Runtime
```rust
pub fn compute_ueba_deviation(
    event: &KronEvent,
    baseline: &UserBaseline,
) -> UEBAFeatures {
    let login_hour = event.ts.hour() as f32;
    let typical_hours = &baseline.typical_login_hours;
    
    // Hour deviation: how far from user's typical hours
    let hour_deviation = typical_hours.iter()
        .map(|&h| (h as f32 - login_hour).abs().min(12.0))
        .min_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(12.0) / 12.0;
    
    // Geo novelty: new country never seen in baseline
    let geo_novelty = if baseline.typical_login_geos
        .contains(&event.src_country) { 0.0 } else { 1.0 };
    
    UEBAFeatures {
        login_hour_deviation: hour_deviation,
        geo_distance_km: compute_geo_distance(event, baseline),
        device_novelty: geo_novelty,
        // ... etc
    }
}
```

---

## Model Registry and Versioning

Models stored at `/var/lib/kron/models/` with version pinning:

```toml
# /etc/kron/models.toml
[models]
anomaly_scorer = { path = "anomaly_scorer_v2.onnx", sha256 = "abc123..." }
ueba_classifier = { path = "ueba_v3.onnx", sha256 = "def456..." }
beacon_detector = { path = "beacon_v1.onnx", sha256 = "ghi789..." }
exfil_scorer = { path = "exfil_v2.onnx", sha256 = "jkl012..." }
multilingual = { path = "summarizer_v1.onnx", sha256 = "mno345..." }
mistral_gguf = { path = "mistral-7b-instruct-q4_k_m.gguf", sha256 = "pqr678..." }
```

Model updates:
1. New model file added to registry with new hash
2. Shadow deployment: new model runs in parallel, output logged but not used
3. A/B test: 10% of inferences use new model for 24 hours
4. Promote: new model becomes primary if metrics improve
5. Rollback: change `models.toml`, models hot-reloaded within 30 seconds

### Feedback Loop for Model Improvement
```rust
// When analyst marks alert as false positive:
pub async fn record_analyst_feedback(
    alert_id: Uuid,
    feedback: AlertFeedback,  // TruePositive | FalsePositive
    db: &ClickHouseClient,
) {
    // Record in training_feedback table
    db.execute("INSERT INTO training_feedback VALUES (?, ?, ?, now())",
        params![alert_id, feedback.to_string(), features_at_alert_time]).await;
    
    // When feedback_count > 1000 for a model, trigger retraining job
    let count = db.query_one::<u64>(
        "SELECT count() FROM training_feedback WHERE model = 'anomaly_scorer' AND applied = false"
    ).await;
    
    if count > 1000 {
        trigger_model_retrain("anomaly_scorer").await;
    }
}
```

---

## AI Privacy Guarantees

1. **No external API calls.** All AI inference is local. Zero bytes of security telemetry sent to OpenAI, Azure OpenAI, Google, Anthropic, or any other cloud AI provider.

2. **Model weights are static.** KRON's inference models do not learn from customer data at inference time. Customer events are never stored in model weights.

3. **Retraining is opt-in.** The feedback loop collects TP/FP labels. Retraining on customer-specific data only happens if the customer explicitly enables it and the data never leaves their infrastructure.

4. **Air-gap compatible.** All models are bundled in the installer. No model downloads required at runtime. Model updates distributed via signed bundles (USB or internal mirror).
