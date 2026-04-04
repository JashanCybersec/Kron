//! MITRE ATT&CK tag extraction from SIGMA rule metadata.
//!
//! SIGMA rules encode ATT&CK information in their `tags` list using the
//! `attack.*` prefix.  [`MitreTagger::extract`] parses those tags into typed
//! [`MitreTag`] values.
//!
//! Tag format examples:
//! - `attack.persistence`        → tactic = "Persistence"
//! - `` `attack.t1055` ``              → `technique_id` = "T1055"
//! - `` `attack.t1055.001` ``          → `technique_id` = "T1055", `sub_technique_id` = Some("001")

/// A single MITRE ATT&CK reference extracted from a SIGMA rule tag.
#[derive(Debug, Clone)]
pub struct MitreTag {
    /// ATT&CK tactic display name (e.g. "Persistence", "Lateral Movement").
    /// `None` when the tag only specifies a technique.
    pub tactic: Option<String>,
    /// ATT&CK technique ID in canonical uppercase form (e.g. "T1055").
    /// `None` when the tag only specifies a tactic.
    pub technique_id: Option<String>,
    /// ATT&CK sub-technique identifier without the leading technique ID
    /// (e.g. "001" for T1055.001).
    pub sub_technique_id: Option<String>,
}

/// Extracts MITRE ATT&CK tags from SIGMA rule tag lists.
pub struct MitreTagger;

impl MitreTagger {
    /// Extract MITRE ATT&CK tags from a list of SIGMA rule tags.
    ///
    /// Only tags prefixed with `attack.` are processed; all others are
    /// silently ignored.
    ///
    /// Recognised patterns (case-insensitive):
    /// - `attack.<tactic-slug>` → tactic display name
    /// - `attack.t<digits>`     → technique ID
    /// - `attack.t<digits>.<sub>` → technique ID + sub-technique
    #[must_use]
    pub fn extract(tags: &[String]) -> Vec<MitreTag> {
        tags.iter().filter_map(|tag| Self::parse_tag(tag)).collect()
    }

    /// Map a SIGMA tactic slug to its MITRE ATT&CK display name.
    ///
    /// Underscores in slugs are replaced by spaces and each word is
    /// capitalised.  Unknown slugs are title-cased on a best-effort basis.
    #[must_use]
    pub fn tactic_display_name(slug: &str) -> String {
        // Known explicit mappings for multi-word tactics that need specific casing.
        match slug.to_lowercase().as_str() {
            "initial_access" => "Initial Access".to_string(),
            "execution" => "Execution".to_string(),
            "persistence" => "Persistence".to_string(),
            "privilege_escalation" => "Privilege Escalation".to_string(),
            "defense_evasion" => "Defense Evasion".to_string(),
            "credential_access" => "Credential Access".to_string(),
            "discovery" => "Discovery".to_string(),
            "lateral_movement" => "Lateral Movement".to_string(),
            "collection" => "Collection".to_string(),
            "command_and_control" => "Command and Control".to_string(),
            "exfiltration" => "Exfiltration".to_string(),
            "impact" => "Impact".to_string(),
            "reconnaissance" => "Reconnaissance".to_string(),
            "resource_development" => "Resource Development".to_string(),
            other => Self::title_case(other),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Parse a single SIGMA tag into a [`MitreTag`], returning `None` if the
    /// tag is not an ATT&CK reference.
    fn parse_tag(tag: &str) -> Option<MitreTag> {
        let lower = tag.to_lowercase();
        let rest = lower.strip_prefix("attack.")?;

        // Technique tag: starts with 't' followed by digits.
        if rest.starts_with('t') && rest.len() > 1 {
            let after_t = &rest[1..];
            // Must have at least one digit right after 't'.
            if after_t.starts_with(|c: char| c.is_ascii_digit()) {
                return Some(Self::parse_technique(after_t));
            }
        }

        // Otherwise treat as a tactic slug.
        Some(MitreTag {
            tactic: Some(Self::tactic_display_name(rest)),
            technique_id: None,
            sub_technique_id: None,
        })
    }

    /// Parse the portion of a technique tag that follows the leading 't'.
    ///
    /// `digits` may be `"1055"` or `"1055.001"`.
    fn parse_technique(digits_and_sub: &str) -> MitreTag {
        if let Some(dot_pos) = digits_and_sub.find('.') {
            let tech_digits = &digits_and_sub[..dot_pos];
            let sub = digits_and_sub[dot_pos + 1..].to_string();
            MitreTag {
                tactic: None,
                technique_id: Some(format!("T{tech_digits}")),
                sub_technique_id: Some(sub),
            }
        } else {
            MitreTag {
                tactic: None,
                technique_id: Some(format!("T{digits_and_sub}")),
                sub_technique_id: None,
            }
        }
    }

    /// Convert a `snake_case` or lowercase slug to Title Case words.
    fn title_case(slug: &str) -> String {
        slug.split('_')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_when_attack_technique_then_correct_id() {
        let tags = vec!["attack.t1055".to_string()];
        let result = MitreTagger::extract(&tags);
        assert_eq!(result.len(), 1);
        let tag = &result[0];
        assert_eq!(tag.technique_id.as_deref(), Some("T1055"));
        assert!(tag.sub_technique_id.is_none());
        assert!(tag.tactic.is_none());
    }

    #[test]
    fn test_extract_when_attack_subtechnique_then_has_sub() {
        let tags = vec!["attack.t1055.001".to_string()];
        let result = MitreTagger::extract(&tags);
        assert_eq!(result.len(), 1);
        let tag = &result[0];
        assert_eq!(tag.technique_id.as_deref(), Some("T1055"));
        assert_eq!(tag.sub_technique_id.as_deref(), Some("001"));
        assert!(tag.tactic.is_none());
    }

    #[test]
    fn test_extract_when_attack_tactic_then_display_name() {
        let tags = vec!["attack.persistence".to_string()];
        let result = MitreTagger::extract(&tags);
        assert_eq!(result.len(), 1);
        let tag = &result[0];
        assert_eq!(tag.tactic.as_deref(), Some("Persistence"));
        assert!(tag.technique_id.is_none());
    }

    #[test]
    fn test_extract_when_lateral_movement_tactic_then_display_name() {
        let tags = vec!["attack.lateral_movement".to_string()];
        let result = MitreTagger::extract(&tags);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tactic.as_deref(), Some("Lateral Movement"));
    }

    #[test]
    fn test_extract_when_non_attack_tag_then_ignored() {
        let tags = vec!["detection.sigma".to_string(), "attack.t1059".to_string()];
        let result = MitreTagger::extract(&tags);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].technique_id.as_deref(), Some("T1059"));
    }

    #[test]
    fn test_extract_when_empty_tags_then_empty_result() {
        let result = MitreTagger::extract(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_tactic_display_name_when_command_and_control_then_correct() {
        assert_eq!(
            MitreTagger::tactic_display_name("command_and_control"),
            "Command and Control"
        );
    }

    #[test]
    fn test_extract_when_mixed_tags_then_all_parsed() {
        let tags = vec![
            "attack.persistence".to_string(),
            "attack.t1053".to_string(),
            "attack.t1053.005".to_string(),
        ];
        let result = MitreTagger::extract(&tags);
        assert_eq!(result.len(), 3);
    }
}
