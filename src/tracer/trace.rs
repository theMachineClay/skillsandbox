use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Trace event types — every action the sandbox takes is recorded.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TraceEventKind {
    // Lifecycle
    SkillStarted,
    SkillCompleted,
    SkillFailed,

    // Network
    DnsResolution,
    NetworkPolicyApplied,
    NetworkPolicyRemoved,
    NetworkEgressAllowed,
    NetworkEgressBlocked,

    // Filesystem
    FileRead,
    FileWrite,
    FileBlocked,

    // Environment
    EnvVarAccess,

    // Syscalls
    SyscallFiltered,
    SyscallBlocked,

    // Execution
    ProcessSpawned,
    Stdout,
    Stderr,
    ExitCode,

    // Policy
    PolicyViolation,
    ResourceLimitHit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub timestamp: DateTime<Utc>,
    pub kind: TraceEventKind,
    pub message: String,
    /// Optional structured data payload (JSON value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl TraceEvent {
    pub fn now(kind: TraceEventKind, message: String) -> Self {
        Self {
            timestamp: Utc::now(),
            kind,
            message,
            data: None,
        }
    }

    pub fn now_with_data(
        kind: TraceEventKind,
        message: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            kind,
            message,
            data: Some(data),
        }
    }
}

// ---------------------------------------------------------------------------
// Execution trace — the full audit record for a single skill run.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub trace_id: String,
    pub skill_name: String,
    pub skill_version: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    pub events: Vec<TraceEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub policy_violations: Vec<TraceEvent>,
    /// Post-execution violation classification summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation_summary: Option<super::classify::ViolationSummary>,
}

// ---------------------------------------------------------------------------
// Tracer — thread-safe event collector with optional real-time streaming.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Tracer {
    inner: Arc<Mutex<ExecutionTrace>>,
    /// When true, every recorded event is also printed to stderr in real-time.
    watch: bool,
}

impl Tracer {
    /// Create a new tracer for a skill execution.
    pub fn new(skill_name: &str, skill_version: &str) -> Self {
        Self::with_watch(skill_name, skill_version, false)
    }

    /// Create a new tracer with optional `--watch` real-time streaming.
    pub fn with_watch(skill_name: &str, skill_version: &str, watch: bool) -> Self {
        let trace = ExecutionTrace {
            trace_id: Uuid::new_v4().to_string(),
            skill_name: skill_name.to_string(),
            skill_version: skill_version.to_string(),
            started_at: Utc::now(),
            completed_at: None,
            events: Vec::new(),
            exit_code: None,
            policy_violations: Vec::new(),
            violation_summary: None,
        };
        Self {
            inner: Arc::new(Mutex::new(trace)),
            watch,
        }
    }

    /// Record a trace event. If watch mode is enabled, also prints to stderr.
    pub fn record(&self, event: TraceEvent) {
        if self.watch {
            self.print_watch_event(&event);
        }
        let is_violation = event.kind == TraceEventKind::PolicyViolation;
        let mut trace = self.inner.lock().unwrap();
        if is_violation {
            trace.policy_violations.push(event.clone());
        }
        trace.events.push(event);
    }

    /// Format and print a single event to stderr for --watch mode.
    fn print_watch_event(&self, event: &TraceEvent) {
        let ts = event.timestamp.format("%H:%M:%S%.3f");
        let (icon, category) = match event.kind {
            // Policy enforcement
            TraceEventKind::NetworkEgressAllowed => ("\x1b[32m✅\x1b[0m", "POLICY  "),
            TraceEventKind::NetworkEgressBlocked => ("\x1b[31m🔒\x1b[0m", "POLICY  "),
            TraceEventKind::NetworkPolicyApplied => ("\x1b[34m🛡️\x1b[0m", "POLICY  "),
            TraceEventKind::NetworkPolicyRemoved => ("\x1b[34m🛡️\x1b[0m", "POLICY  "),
            TraceEventKind::PolicyViolation     => ("\x1b[31m🚨\x1b[0m", "VIOLATE "),
            TraceEventKind::EnvVarAccess        => ("\x1b[33m🔒\x1b[0m", "POLICY  "),

            // Filesystem
            TraceEventKind::FileRead    => ("\x1b[36m📂\x1b[0m", "FS      "),
            TraceEventKind::FileWrite   => ("\x1b[36m📂\x1b[0m", "FS      "),
            TraceEventKind::FileBlocked => ("\x1b[31m🔒\x1b[0m", "FS      "),

            // Syscalls
            TraceEventKind::SyscallFiltered => ("\x1b[33m🔧\x1b[0m", "SECCOMP "),
            TraceEventKind::SyscallBlocked  => ("\x1b[31m🔒\x1b[0m", "SECCOMP "),

            // Output
            TraceEventKind::Stdout => ("\x1b[37m📋\x1b[0m", "STDOUT  "),
            TraceEventKind::Stderr => ("\x1b[33m📋\x1b[0m", "STDERR  "),

            // Lifecycle
            TraceEventKind::SkillStarted   => ("\x1b[32m▶\x1b[0m",  "START   "),
            TraceEventKind::SkillCompleted => ("\x1b[32m✅\x1b[0m", "COMPLETE"),
            TraceEventKind::SkillFailed    => ("\x1b[31m❌\x1b[0m", "FAILED  "),

            // Other
            TraceEventKind::DnsResolution    => ("\x1b[36m🔍\x1b[0m", "DNS     "),
            TraceEventKind::ProcessSpawned   => ("\x1b[34m⚙️\x1b[0m", "PROCESS "),
            TraceEventKind::ExitCode         => ("\x1b[34m⏹\x1b[0m",  "EXIT    "),
            TraceEventKind::ResourceLimitHit => ("\x1b[31m⚠️\x1b[0m", "LIMIT   "),
        };

        // Truncate long messages for readability (full data is in trace.json)
        let msg = if event.message.len() > 120 {
            format!("{}...", &event.message[..117])
        } else {
            event.message.clone()
        };

        // Append violation classification tag if applicable
        let tag = super::classify::classify_event_tag(event);

        eprintln!("[{ts}] {icon} {category} {msg}{tag}");
    }

    /// Mark the execution as completed and classify violations.
    pub fn complete(&self, exit_code: i32) {
        let mut trace = self.inner.lock().unwrap();
        trace.completed_at = Some(Utc::now());
        trace.exit_code = Some(exit_code);

        // Classify enforcement events
        let summary = super::classify::classify_trace(&trace);
        let has_enforcements = summary.total_enforcements > 0;
        trace.violation_summary = if has_enforcements {
            Some(summary.clone())
        } else {
            None
        };

        let duration = trace
            .completed_at
            .map(|c| (c - trace.started_at).to_std().unwrap_or_default())
            .map(|d| format!("{:.0}ms", d.as_millis()))
            .unwrap_or_else(|| "?".to_string());
        let violations = trace.policy_violations.len();

        let classification_tag = if has_enforcements {
            format!(
                "  classified=[{}] max_severity={}",
                summary.classes.join(", "),
                summary.max_severity,
            )
        } else {
            String::new()
        };

        let event = TraceEvent::now(
            if exit_code == 0 {
                TraceEventKind::SkillCompleted
            } else {
                TraceEventKind::SkillFailed
            },
            format!(
                "exit_code={}  duration={}  violations={}{}{}",
                exit_code,
                duration,
                violations,
                if violations > 0 {
                    format!(" ({} prevented)", violations)
                } else {
                    String::new()
                },
                classification_tag,
            ),
        );

        if self.watch {
            self.print_watch_event(&event);
        }
        trace.events.push(event);
    }

    /// Get a snapshot of the current trace.
    pub fn snapshot(&self) -> ExecutionTrace {
        self.inner.lock().unwrap().clone()
    }

    /// Serialize the trace to JSON.
    pub fn to_json(&self) -> String {
        let trace = self.snapshot();
        serde_json::to_string_pretty(&trace).unwrap_or_else(|_| "{}".to_string())
    }

    /// Write the trace to a file.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let json = self.to_json();
        std::fs::write(path, json)
    }

    /// Summary for terminal output.
    pub fn summary(&self) -> String {
        let trace = self.snapshot();
        let duration = trace
            .completed_at
            .map(|c| (c - trace.started_at).to_std().unwrap_or_default())
            .map(|d| format!("{:.2}s", d.as_secs_f64()))
            .unwrap_or_else(|| "running".to_string());

        let violations = trace.policy_violations.len();
        let exit = trace
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "?".to_string());

        format!(
            "Trace {} | skill={} v{} | duration={} | exit={} | events={} | violations={}",
            &trace.trace_id[..8],
            trace.skill_name,
            trace.skill_version,
            duration,
            exit,
            trace.events.len(),
            violations,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracer_records_events() {
        let tracer = Tracer::new("test-skill", "0.1.0");
        tracer.record(TraceEvent::now(
            TraceEventKind::SkillStarted,
            "test started".to_string(),
        ));
        tracer.record(TraceEvent::now(
            TraceEventKind::PolicyViolation,
            "blocked egress to webhook.site".to_string(),
        ));
        tracer.complete(0);

        let trace = tracer.snapshot();
        assert_eq!(trace.skill_name, "test-skill");
        assert_eq!(trace.events.len(), 3); // started + violation + completed
        assert_eq!(trace.policy_violations.len(), 1);
        assert_eq!(trace.exit_code, Some(0));
    }

    #[test]
    fn trace_serializes_to_json() {
        let tracer = Tracer::new("weather-lookup", "0.1.0");
        tracer.record(TraceEvent::now(
            TraceEventKind::NetworkEgressAllowed,
            "ALLOW api.openweathermap.org:443/tcp".to_string(),
        ));
        tracer.complete(0);

        let json = tracer.to_json();
        assert!(json.contains("weather-lookup"));
        assert!(json.contains("network_egress_allowed"));
    }

    #[test]
    fn watch_mode_still_records_events() {
        // Watch mode should record events exactly the same as normal mode
        // (the stderr printing is a side effect we don't assert here)
        let tracer = Tracer::with_watch("watched-skill", "0.2.0", true);
        tracer.record(TraceEvent::now(
            TraceEventKind::SkillStarted,
            "starting".to_string(),
        ));
        tracer.record(TraceEvent::now(
            TraceEventKind::NetworkEgressBlocked,
            "BLOCKED webhook.site:443".to_string(),
        ));
        tracer.record(TraceEvent::now(
            TraceEventKind::PolicyViolation,
            "undeclared egress attempt".to_string(),
        ));
        tracer.complete(0);

        let trace = tracer.snapshot();
        assert_eq!(trace.events.len(), 4); // started + blocked + violation + completed
        assert_eq!(trace.policy_violations.len(), 1);
        assert!(trace.completed_at.is_some());
    }
}
