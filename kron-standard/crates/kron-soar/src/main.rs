//! `kron-soar` — SOAR playbook engine for the KRON SIEM platform.
//!
//! Executes automated response playbooks triggered by analyst actions
//! (WhatsApp reply, mobile app, web UI) or by autopilot mode.
//!
//! # Autopilot mode
//!
//! Zero-staff organizations can enable autopilot. Safe actions (block IP,
//! disable account) execute automatically. Destructive actions always require
//! human confirmation with biometric on mobile.
//!
//! # Playbook actions
//!
//! - Block IP in iptables/AWS Security Group
//! - Isolate host (network quarantine)
//! - Disable AD/LDAP account
//! - Create incident ticket
//! - Collect forensic artifacts
//! - Escalate to CERT-In (breach notification workflow)

fn main() {
    // TODO(#6, hardik, phase-4): implement SOAR engine entrypoint
    // Blocked on: kron-alert (Phase 2), playbook schema definition (Phase 4).
}
