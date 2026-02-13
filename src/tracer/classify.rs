//! Violation classification for SkillSandbox execution traces.
//!
//! Post-processes a completed trace to classify enforcement events into
//! threat categories. This bridges sandbox enforcement (what was blocked)
//! with security intelligence (why it matters).
//!
//! Classification taxonomy derived from real incidents:
//! - Clay/ClawBot PII leaks (Incidents 1 & 2)
//! - ClawdHub credential stealer (Incident 3)
//!
//! # Example trace output with classification:
//!
//! ```json
//! {
//!   "violation_summary": {
//!     "total_enforcements": 4,
//!     "classifications": [
//!       {
//!         "class": "credential_harvesting",
//!         "severity": "critical",
//!         "description": "Sensitive credentials stripped from environment",
//!         "prevented_by": "env_filter",
//!         "count": 1
//!       },
//!       {
//!         "class": "credential_exfiltration",
//!         "severity": "critical",
//!         "description": "Network egress to undeclared domain blocked",
//!         "prevented_by": "network_egress_policy",
//!         "count": 1
//!       }
//!     ],
//!     "all_prevented": true
//!   }
//! }
//! ```

use crate::tracer::{ExecutionTrace, TraceEvent, TraceEventKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Violation classes — the taxonomy of what the sandbox prevented.
// ---------------------------------------------------------------------------

/// A classified threat that the sandbox's enforcement layer prevented.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ViolationClass {
    /// Sensitive credentials stripped from environment before skill execution.
    /// The skill never saw AWS keys, API tokens, etc.
    /// Prevented by: env_filter
    CredentialHarvesting,

    /// Network egress to an undeclared domain was blocked.
    /// The skill attempted to send data to a server not in its manifest.
    /// Prevented by: network_egress_policy
    CredentialExfiltration,

    /// Generic data exfiltration — network egress blocked, but no credential
    /// context detected. Could be telemetry, tracking, or benign.
    /// Prevented by: network_egress_policy
    DataExfiltration,

    /// Filesystem access outside declared paths was denied.
    /// The skill tried to read/write files it didn't declare.
    /// Prevented by: filesystem_isolation
    UnauthorizedFileAccess,

    /// A dangerous syscall was blocked by seccomp-bpf.
    /// Includes ptrace, mount, keyctl, etc.
    /// Prevented by: seccomp_bpf
    PrivilegeEscalation,

    /// Resource limit was hit (memory, CPU, timeout).
    /// Prevented by: resource_limits
    ResourceAbuse,

    /// Combined pattern: credential harvesting + exfiltration attempt.
    /// This is the ClawdHub credential stealer pattern.
    /// Prevented by: multiple layers
    SupplyChainAttack,
}

impl ViolationClass {
    pub fn severity(&self) -> &'static str {
        match self {
            Self::SupplyChainAttack => "critical",
            Self::CredentialExfiltration => "critical",
            Self::CredentialHarvesting => "critical",
            Self::PrivilegeEscalation => "high",
            Self::UnauthorizedFileAccess => "high",
            Self::DataExfiltration => "medium",
            Self::ResourceAbuse => "medium",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::CredentialHarvesting => "Sensitive credentials stripped from environment",
            Self::CredentialExfiltration => "Network egress to undeclared domain blocked",
            Self::DataExfiltration => "Network egress to undeclared domain blocked (no credential context)",
            Self::UnauthorizedFileAccess => "Filesystem access outside declared paths denied",
            Self::PrivilegeEscalation => "Dangerous syscall blocked by seccomp-bpf",
            Self::ResourceAbuse => "Resource limit exceeded",
            Self::SupplyChainAttack => "Combined credential harvesting + exfiltration attempt (supply chain attack pattern)",
        }
    }

    pub fn prevented_by(&self) -> &'static str {
        match self {
            Self::CredentialHarvesting => "env_filter",
            Self::CredentialExfiltration => "network_egress_policy",
            Self::DataExfiltration => "network_egress_policy",
            Self::UnauthorizedFileAccess => "filesystem_isolation",
            Self::PrivilegeEscalation => "seccomp_bpf",
            Self::ResourceAbuse => "resource_limits",
            Self::SupplyChainAttack => "env_filter + network_egress_policy",
        }
    }

    pub fn mitre_tactic(&self) -> &'static str {
        match self {
            Self::CredentialHarvesting => "credential-access",
            Self::CredentialExfiltration => "exfiltration",
            Self::DataExfiltration => "exfiltration",
            Self::UnauthorizedFileAccess => "collection",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::ResourceAbuse => "impact",
            Self::SupplyChainAttack => "exfiltration",
        }
    }
}

// ---------------------------------------------------------------------------
// Classification output — added to trace JSON.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedViolation {
    pub class: ViolationClass,
    pub severity: String,
    pub description: String,
    pub prevented_by: String,
    pub mitre_tactic: String,
    pub count: usize,
    /// The event messages that contributed to this classification.
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationSummary {
    pub total_enforcements: usize,
    pub classifications: Vec<ClassifiedViolation>,
    pub all_prevented: bool,
    /// Unique violation classes present.
    pub classes: Vec<String>,
    /// Highest severity across all classifications.
    pub max_severity: String,
}

// ---------------------------------------------------------------------------
// Known high-value credential patterns in env var names.
// ---------------------------------------------------------------------------

const HIGH_VALUE_CREDENTIAL_PATTERNS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_SECRET_KEY",
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "MYSQL_PASSWORD",
    "DOCKER_PASSWORD",
    "NPM_TOKEN",
    "SLACK_TOKEN",
    "AZURE_CLIENT_SECRET",
    "COHERE_API_KEY",
    "_KEY",
    "_SECRET",
    "_TOKEN",
    "_PASSWORD",
];

/// Check if an env var filter message references a high-value credential.
fn is_high_value_credential_message(msg: &str) -> bool {
    let upper = msg.to_uppercase();
    HIGH_VALUE_CREDENTIAL_PATTERNS
        .iter()
        .any(|pat| upper.contains(pat))
}

// ---------------------------------------------------------------------------
// Classification logic.
// ---------------------------------------------------------------------------

/// Classify a single trace event into zero or more violation classes.
fn classify_event(event: &TraceEvent) -> Vec<ViolationClass> {
    match event.kind {
        // Env filtering that caught credentials
        TraceEventKind::EnvVarAccess => {
            // "Environment filtered: X vars allowed, Y vars stripped"
            if event.message.contains("stripped") || event.message.contains("filtered") {
                // Check if high-value creds were among those stripped
                if is_high_value_credential_message(&event.message) {
                    return vec![ViolationClass::CredentialHarvesting];
                }
                // Generic env filtering — still noteworthy but lower severity
                // Only classify if a significant number were stripped
                if let Some(count) = extract_stripped_count(&event.message) {
                    if count > 5 {
                        return vec![ViolationClass::CredentialHarvesting];
                    }
                }
            }
            vec![]
        }

        // Network egress blocked
        TraceEventKind::NetworkEgressBlocked => {
            vec![ViolationClass::CredentialExfiltration]
        }

        // Filesystem access denied
        TraceEventKind::FileBlocked => {
            // Check for known sensitive paths
            if event.message.contains(".aws")
                || event.message.contains(".ssh")
                || event.message.contains(".gnupg")
                || event.message.contains("credentials")
            {
                vec![ViolationClass::CredentialHarvesting]
            } else {
                vec![ViolationClass::UnauthorizedFileAccess]
            }
        }

        // Dangerous syscall blocked
        TraceEventKind::SyscallBlocked => {
            vec![ViolationClass::PrivilegeEscalation]
        }

        // Resource limit hit
        TraceEventKind::ResourceLimitHit => {
            vec![ViolationClass::ResourceAbuse]
        }

        // Explicit policy violation
        TraceEventKind::PolicyViolation => {
            // Could be any class — look at message for hints
            if event.message.to_lowercase().contains("egress")
                || event.message.to_lowercase().contains("network")
            {
                vec![ViolationClass::CredentialExfiltration]
            } else if event.message.to_lowercase().contains("env")
                || event.message.to_lowercase().contains("credential")
            {
                vec![ViolationClass::CredentialHarvesting]
            } else {
                vec![ViolationClass::DataExfiltration]
            }
        }

        _ => vec![],
    }
}

/// Try to extract the stripped count from a message like "Environment filtered: 2 vars allowed, 59 vars stripped"
fn extract_stripped_count(msg: &str) -> Option<usize> {
    let words: Vec<&str> = msg.split_whitespace().collect();
    // Look for pattern "N vars stripped" (3-word window)
    for window in words.windows(3) {
        if window[2] == "stripped" || window[2].starts_with("strip") {
            if let Ok(n) = window[0].parse::<usize>() {
                return Some(n);
            }
        }
    }
    // Also try "N stripped" (2-word window)
    for window in words.windows(2) {
        if window[1] == "stripped" || window[1].starts_with("strip") {
            if let Ok(n) = window[0].parse::<usize>() {
                return Some(n);
            }
        }
    }
    // Also try "blocked=N"
    if let Some(rest) = msg.find("blocked=").map(|i| &msg[i + 8..]) {
        if let Ok(n) = rest.split_whitespace().next().unwrap_or("").parse::<usize>() {
            return Some(n);
        }
    }
    None
}

/// Detect the supply chain attack pattern: credential harvesting + exfiltration.
fn detect_supply_chain_pattern(classes: &[ViolationClass]) -> bool {
    let has_harvesting = classes.contains(&ViolationClass::CredentialHarvesting);
    let has_exfiltration = classes.contains(&ViolationClass::CredentialExfiltration)
        || classes.contains(&ViolationClass::DataExfiltration);
    has_harvesting && has_exfiltration
}

/// Classify all events in a completed execution trace.
///
/// Returns a `ViolationSummary` that can be added to the trace JSON.
pub fn classify_trace(trace: &ExecutionTrace) -> ViolationSummary {
    // Collect all classifications
    let mut all_classes: Vec<(ViolationClass, String)> = Vec::new();
    for event in &trace.events {
        let classes = classify_event(event);
        for class in classes {
            all_classes.push((class, event.message.clone()));
        }
    }

    // Aggregate by class
    let mut class_map: HashMap<ViolationClass, Vec<String>> = HashMap::new();
    for (class, evidence) in &all_classes {
        class_map
            .entry(class.clone())
            .or_default()
            .push(evidence.clone());
    }

    // Check for supply chain attack pattern
    let raw_classes: Vec<ViolationClass> = all_classes.iter().map(|(c, _)| c.clone()).collect();
    let is_supply_chain = detect_supply_chain_pattern(&raw_classes);

    // Build classified violations
    let mut classifications: Vec<ClassifiedViolation> = class_map
        .iter()
        .map(|(class, evidence)| ClassifiedViolation {
            class: class.clone(),
            severity: class.severity().to_string(),
            description: class.description().to_string(),
            prevented_by: class.prevented_by().to_string(),
            mitre_tactic: class.mitre_tactic().to_string(),
            count: evidence.len(),
            evidence: evidence.clone(),
        })
        .collect();

    // Add supply chain attack classification if detected
    if is_supply_chain {
        let supply_chain_evidence: Vec<String> = all_classes
            .iter()
            .filter(|(c, _)| {
                matches!(
                    c,
                    ViolationClass::CredentialHarvesting
                        | ViolationClass::CredentialExfiltration
                        | ViolationClass::DataExfiltration
                )
            })
            .map(|(_, e)| e.clone())
            .collect();

        classifications.push(ClassifiedViolation {
            class: ViolationClass::SupplyChainAttack,
            severity: ViolationClass::SupplyChainAttack.severity().to_string(),
            description: ViolationClass::SupplyChainAttack.description().to_string(),
            prevented_by: ViolationClass::SupplyChainAttack.prevented_by().to_string(),
            mitre_tactic: ViolationClass::SupplyChainAttack.mitre_tactic().to_string(),
            count: 1,
            evidence: supply_chain_evidence,
        });
    }

    // Sort by severity (critical first)
    classifications.sort_by(|a, b| {
        let severity_order = |s: &str| match s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            _ => 3,
        };
        severity_order(&a.severity).cmp(&severity_order(&b.severity))
    });

    let total = classifications.iter().map(|c| c.count).sum();
    let class_names: Vec<String> = classifications
        .iter()
        .map(|c| format!("{:?}", c.class).to_lowercase())
        .collect();
    let max_severity = classifications
        .first()
        .map(|c| c.severity.clone())
        .unwrap_or_else(|| "none".to_string());

    ViolationSummary {
        total_enforcements: total,
        classifications,
        all_prevented: true, // If we got here, the skill completed under enforcement
        classes: class_names,
        max_severity,
    }
}

// ---------------------------------------------------------------------------
// Integration: extend the watch-mode output with classification tags.
// ---------------------------------------------------------------------------

/// Format a classification tag for --watch output.
/// Returns something like " [CREDENTIAL_HARVESTING]" or "" if no classification.
pub fn classify_event_tag(event: &TraceEvent) -> String {
    let classes = classify_event(event);
    if classes.is_empty() {
        return String::new();
    }
    let tags: Vec<String> = classes
        .iter()
        .map(|c| format!("{:?}", c).to_uppercase())
        .collect();
    format!(" \x1b[31m[{}]\x1b[0m", tags.join(", "))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_event(kind: TraceEventKind, msg: &str) -> TraceEvent {
        TraceEvent {
            timestamp: Utc::now(),
            kind,
            message: msg.to_string(),
            data: None,
        }
    }

    fn make_trace(events: Vec<TraceEvent>) -> ExecutionTrace {
        ExecutionTrace {
            trace_id: "test-trace-id".to_string(),
            skill_name: "test-skill".to_string(),
            skill_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            events,
            exit_code: Some(0),
            policy_violations: vec![],
            violation_summary: None,
        }
    }

    #[test]
    fn classifies_credential_harvesting_from_env_filter() {
        let trace = make_trace(vec![make_event(
            TraceEventKind::EnvVarAccess,
            "Environment filtered: 2 vars allowed, 59 vars stripped",
        )]);
        let summary = classify_trace(&trace);
        assert!(summary.total_enforcements > 0);
        assert!(summary
            .classifications
            .iter()
            .any(|c| c.class == ViolationClass::CredentialHarvesting));
    }

    #[test]
    fn classifies_network_block_as_exfiltration() {
        let trace = make_trace(vec![make_event(
            TraceEventKind::NetworkEgressBlocked,
            "DEFAULT DENY — all undeclared egress blocked",
        )]);
        let summary = classify_trace(&trace);
        assert!(summary
            .classifications
            .iter()
            .any(|c| c.class == ViolationClass::CredentialExfiltration));
    }

    #[test]
    fn detects_supply_chain_attack_pattern() {
        let trace = make_trace(vec![
            make_event(
                TraceEventKind::EnvVarAccess,
                "Environment filtered: 2 vars allowed, 59 vars stripped",
            ),
            make_event(
                TraceEventKind::NetworkEgressBlocked,
                "BLOCKED webhook.site:443 — not in manifest",
            ),
        ]);
        let summary = classify_trace(&trace);
        assert!(
            summary
                .classifications
                .iter()
                .any(|c| c.class == ViolationClass::SupplyChainAttack),
            "Should detect supply chain attack pattern (harvesting + exfiltration)"
        );
        assert_eq!(summary.max_severity, "critical");
    }

    #[test]
    fn classifies_filesystem_block() {
        let trace = make_trace(vec![make_event(
            TraceEventKind::FileBlocked,
            "BLOCKED read: /home/user/.aws/credentials",
        )]);
        let summary = classify_trace(&trace);
        assert!(summary
            .classifications
            .iter()
            .any(|c| c.class == ViolationClass::CredentialHarvesting));
    }

    #[test]
    fn empty_trace_produces_empty_summary() {
        let trace = make_trace(vec![make_event(
            TraceEventKind::SkillStarted,
            "starting".to_string().as_str(),
        )]);
        let summary = classify_trace(&trace);
        assert_eq!(summary.total_enforcements, 0);
        assert!(summary.classifications.is_empty());
        assert_eq!(summary.max_severity, "none");
    }

    #[test]
    fn classify_event_tag_formats_correctly() {
        let event = make_event(
            TraceEventKind::NetworkEgressBlocked,
            "BLOCKED webhook.site",
        );
        let tag = classify_event_tag(&event);
        assert!(tag.contains("CREDENTIALEXFILTRATION"));
    }
}
