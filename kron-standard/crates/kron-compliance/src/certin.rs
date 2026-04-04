//! CERT-In Directions 2022 — compliance mapping module.
//!
//! Maps KRON alert categories to the 13 reportable incident categories defined
//! by CERT-In (Computer Emergency Response Team — India) under the IT
//! (Amendment) Act 2008 and the 2022 Directions.
//!
//! # Reportable categories
//!
//! 1. Targeted scanning/probing of critical networks or systems
//! 2. Compromise of critical systems/information
//! 3. Unauthorised access to IT systems/data
//! 4. Defacement of website or intrusion into a website
//! 5. Malicious code attacks (virus, worm, Trojan, ransomware, spyware)
//! 6. Attacks on servers (database, mail, DNS) and network devices (routers)
//! 7. Identity theft, spoofing, phishing attacks
//! 8. Denial of Service (DoS) and Distributed DoS attacks
//! 9. Attacks on critical infrastructure, SCADA, operational technology systems
//! 10. Attacks on applications (e-governance, e-commerce)
//! 11. Data breach
//! 12. Data leak
//! 13. Attacks on Internet of Things (IoT) devices and associated systems
//!
//! Organisations must report to CERT-In within **6 hours** of noticing the incident.

use serde::{Deserialize, Serialize};

use crate::error::ComplianceError;

/// All 13 CERT-In Directions 2022 reportable incident categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertInCategory {
    /// Category 1: Targeted scanning/probing of critical networks.
    TargetedScanningProbing,
    /// Category 2: Compromise of critical systems or information.
    CriticalSystemCompromise,
    /// Category 3: Unauthorised access to IT systems or data.
    UnauthorisedAccess,
    /// Category 4: Website defacement or intrusion.
    WebsiteDefacement,
    /// Category 5: Malicious code (virus, worm, Trojan, ransomware, spyware).
    MaliciousCode,
    /// Category 6: Attacks on servers and network devices.
    ServerNetworkAttack,
    /// Category 7: Identity theft, spoofing, phishing.
    IdentityTheftPhishing,
    /// Category 8: DoS and DDoS attacks.
    DosAttack,
    /// Category 9: Attacks on critical infrastructure, SCADA/OT systems.
    CriticalInfrastructureAttack,
    /// Category 10: Attacks on applications (e-governance, e-commerce).
    ApplicationAttack,
    /// Category 11: Data breach (unauthorised exfiltration confirmed).
    DataBreach,
    /// Category 12: Data leak (unintentional exposure).
    DataLeak,
    /// Category 13: Attacks on IoT devices.
    IotAttack,
}

impl CertInCategory {
    /// Returns the official CERT-In category number (1–13).
    #[must_use]
    pub fn number(self) -> u8 {
        match self {
            Self::TargetedScanningProbing => 1,
            Self::CriticalSystemCompromise => 2,
            Self::UnauthorisedAccess => 3,
            Self::WebsiteDefacement => 4,
            Self::MaliciousCode => 5,
            Self::ServerNetworkAttack => 6,
            Self::IdentityTheftPhishing => 7,
            Self::DosAttack => 8,
            Self::CriticalInfrastructureAttack => 9,
            Self::ApplicationAttack => 10,
            Self::DataBreach => 11,
            Self::DataLeak => 12,
            Self::IotAttack => 13,
        }
    }

    /// Returns the official CERT-In category description.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::TargetedScanningProbing => {
                "Targeted scanning/probing of critical networks or systems"
            }
            Self::CriticalSystemCompromise => "Compromise of critical systems/information",
            Self::UnauthorisedAccess => "Unauthorised access to IT systems/data",
            Self::WebsiteDefacement => {
                "Defacement of website or intrusion into a website and related systems"
            }
            Self::MaliciousCode => {
                "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/\
                 Spyware/Ransomware/Cryptominers"
            }
            Self::ServerNetworkAttack => {
                "Attacks on servers such as Database, Mail and DNS and Network devices \
                 such as Routers"
            }
            Self::IdentityTheftPhishing => {
                "Identity Theft, Spoofing and Phishing attacks"
            }
            Self::DosAttack => {
                "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks"
            }
            Self::CriticalInfrastructureAttack => {
                "Attacks on Critical infrastructure, SCADA, Operational Technology Systems \
                 and Wireless networks"
            }
            Self::ApplicationAttack => {
                "Attacks on Applications such as E-Governance, E-Commerce etc."
            }
            Self::DataBreach => "Data Breach",
            Self::DataLeak => "Data Leak",
            Self::IotAttack => {
                "Attacks on Internet of Things (IoT) devices and associated systems, \
                 networks and infrastructure"
            }
        }
    }

    /// Returns all 13 categories in order.
    #[must_use]
    pub fn all() -> [Self; 13] {
        [
            Self::TargetedScanningProbing,
            Self::CriticalSystemCompromise,
            Self::UnauthorisedAccess,
            Self::WebsiteDefacement,
            Self::MaliciousCode,
            Self::ServerNetworkAttack,
            Self::IdentityTheftPhishing,
            Self::DosAttack,
            Self::CriticalInfrastructureAttack,
            Self::ApplicationAttack,
            Self::DataBreach,
            Self::DataLeak,
            Self::IotAttack,
        ]
    }
}

impl std::fmt::Display for CertInCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Category {}: {}", self.number(), self.description())
    }
}

/// Maps a KRON `event_type` or MITRE tactic string to the closest CERT-In category.
///
/// Returns the best-match category, or `ComplianceError::UnknownCertInCategory`
/// if the input cannot be mapped.
///
/// # Arguments
/// * `event_type` — The KRON event_type string or MITRE tactic name.
///
/// # Errors
///
/// Returns `ComplianceError::UnknownCertInCategory` if no mapping exists.
pub fn map_event_type(event_type: &str) -> Result<CertInCategory, ComplianceError> {
    let lower = event_type.to_lowercase();
    let category = if lower.contains("scan") || lower.contains("probe") || lower.contains("recon")
    {
        CertInCategory::TargetedScanningProbing
    } else if lower.contains("ransomware")
        || lower.contains("malware")
        || lower.contains("virus")
        || lower.contains("worm")
        || lower.contains("trojan")
        || lower.contains("cryptominer")
    {
        CertInCategory::MaliciousCode
    } else if lower.contains("phish") || lower.contains("spoof") || lower.contains("identity") {
        CertInCategory::IdentityTheftPhishing
    } else if lower.contains("ddos") || lower.contains("dos") || lower.contains("flood") {
        CertInCategory::DosAttack
    } else if lower.contains("breach") || lower.contains("exfil") {
        CertInCategory::DataBreach
    } else if lower.contains("leak") || lower.contains("exposure") {
        CertInCategory::DataLeak
    } else if lower.contains("defac") || lower.contains("tamper") {
        CertInCategory::WebsiteDefacement
    } else if lower.contains("unauth") || lower.contains("privilege") || lower.contains("lateral")
    {
        CertInCategory::UnauthorisedAccess
    } else if lower.contains("scada") || lower.contains("ot/") || lower.contains("ics") {
        CertInCategory::CriticalInfrastructureAttack
    } else if lower.contains("iot") || lower.contains("embedded") {
        CertInCategory::IotAttack
    } else if lower.contains("web app") || lower.contains("application") || lower.contains("sqli")
    {
        CertInCategory::ApplicationAttack
    } else if lower.contains("server") || lower.contains("dns") || lower.contains("mail") {
        CertInCategory::ServerNetworkAttack
    } else if lower.contains("compromi") || lower.contains("rootkit") || lower.contains("persist")
    {
        CertInCategory::CriticalSystemCompromise
    } else {
        return Err(ComplianceError::UnknownCertInCategory(
            event_type.to_owned(),
        ));
    };
    Ok(category)
}

/// Generates the body text for a CERT-In incident report for a single incident.
///
/// Output is a structured plain-text block matching the CERT-In prescribed format.
/// Callers embed this in the HTML report or send directly via email/portal.
///
/// # Arguments
/// * `category`        — The CERT-In category the incident falls under.
/// * `incident_id`     — Unique incident/alert ID from KRON.
/// * `detected_at`     — ISO-8601 timestamp of first detection.
/// * `description`     — Human-readable incident description.
/// * `affected_system` — Hostname or IP of the affected system.
/// * `tenant_name`     — Reporting organisation name.
#[must_use]
pub fn format_incident_report(
    category: CertInCategory,
    incident_id: &str,
    detected_at: &str,
    description: &str,
    affected_system: &str,
    tenant_name: &str,
) -> String {
    format!(
        "CERT-In Incident Report\n\
         ========================\n\
         Organisation : {tenant_name}\n\
         Incident ID  : {incident_id}\n\
         Category No. : {cat_num}\n\
         Category     : {cat_desc}\n\
         Detected At  : {detected_at}\n\
         Affected     : {affected_system}\n\
         \n\
         Description\n\
         -----------\n\
         {description}\n\
         \n\
         [Report generated by KRON SIEM — submit to incident@cert-in.org.in within 6 hours]\n",
        cat_num = category.number(),
        cat_desc = category.description(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_categories_have_unique_numbers() {
        let nums: Vec<u8> = CertInCategory::all().iter().map(|c| c.number()).collect();
        let mut deduped = nums.clone();
        deduped.dedup();
        assert_eq!(nums.len(), 13);
        assert_eq!(nums.len(), deduped.len());
    }

    #[test]
    fn test_map_event_type_when_ransomware_then_malicious_code() {
        let cat = map_event_type("ransomware_detected").unwrap();
        assert_eq!(cat, CertInCategory::MaliciousCode);
    }

    #[test]
    fn test_map_event_type_when_ddos_then_dos_attack() {
        let cat = map_event_type("ddos_flood").unwrap();
        assert_eq!(cat, CertInCategory::DosAttack);
    }

    #[test]
    fn test_map_event_type_when_phishing_then_identity_theft() {
        let cat = map_event_type("phishing_link_clicked").unwrap();
        assert_eq!(cat, CertInCategory::IdentityTheftPhishing);
    }

    #[test]
    fn test_map_event_type_when_unknown_then_error() {
        let result = map_event_type("completely_unknown_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_incident_report_contains_cert_in_header() {
        let report = format_incident_report(
            CertInCategory::DataBreach,
            "alert-001",
            "2026-03-25T00:00:00Z",
            "Customer PII exfiltrated via SQL injection.",
            "db-prod-01",
            "Acme Corp",
        );
        assert!(report.contains("CERT-In Incident Report"));
        assert!(report.contains("Category No. : 11"));
        assert!(report.contains("Acme Corp"));
    }
}
