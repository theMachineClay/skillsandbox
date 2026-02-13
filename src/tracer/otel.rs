//! OpenTelemetry span export for SkillSandbox execution traces.
//!
//! Converts a completed `ExecutionTrace` into OpenTelemetry spans and exports
//! them via OTLP HTTP to any OTel-compatible backend (Jaeger, Grafana Tempo,
//! Datadog, etc.).
//!
//! This is the first sandbox to emit enforcement events as OTel spans —
//! bridging sandbox security with the industry-standard observability pipeline.
//!
//! # Span tree structure
//!
//! ```text
//! skill_execution (root span)
//! ├── sandbox.policy.env_filter      {sandbox.env.allowed: 4, sandbox.env.stripped: 65}
//! ├── sandbox.policy.network_allow   {sandbox.net.domain: "api.weather.org"}
//! ├── sandbox.policy.network_deny    {sandbox.net.action: "DROP"}
//! ├── sandbox.skill.stdout           {sandbox.output.line: "..."}
//! ├── sandbox.skill.stderr           {sandbox.output.line: "..."}
//! └── sandbox.skill.exit             {sandbox.exit_code: 0, sandbox.duration_ms: 199}
//! ```

use crate::tracer::{ExecutionTrace, TraceEvent, TraceEventKind};
use anyhow::{Context, Result};
use opentelemetry::trace::{Status, Tracer, TraceContextExt, TracerProvider};
use opentelemetry::KeyValue;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

/// Initialize the OTel tracer provider with OTLP HTTP exporter.
///
/// Respects standard OTel env vars:
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` (default: http://localhost:4318)
/// - `OTEL_SERVICE_NAME` (default: skillsandbox)
fn init_tracer_provider() -> Result<SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_http()
        .build()
        .context("Failed to build OTLP span exporter")?;

    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .unwrap_or_else(|_| "skillsandbox".to_string());

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder_empty()
                .with_attributes([
                    KeyValue::new("service.name", service_name),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                ])
                .build(),
        )
        .build();

    Ok(provider)
}

/// Map a TraceEventKind to a span name following `sandbox.*` namespace.
fn span_name(kind: &TraceEventKind) -> &'static str {
    match kind {
        // Policy enforcement
        TraceEventKind::NetworkEgressAllowed => "sandbox.policy.network_allow",
        TraceEventKind::NetworkEgressBlocked => "sandbox.policy.network_deny",
        TraceEventKind::NetworkPolicyApplied => "sandbox.policy.network_setup",
        TraceEventKind::NetworkPolicyRemoved => "sandbox.policy.network_teardown",
        TraceEventKind::EnvVarAccess => "sandbox.policy.env_filter",
        TraceEventKind::PolicyViolation => "sandbox.policy.violation",

        // Filesystem
        TraceEventKind::FileRead => "sandbox.fs.read",
        TraceEventKind::FileWrite => "sandbox.fs.write",
        TraceEventKind::FileBlocked => "sandbox.fs.blocked",

        // Syscalls
        TraceEventKind::SyscallFiltered => "sandbox.seccomp.setup",
        TraceEventKind::SyscallBlocked => "sandbox.seccomp.blocked",

        // Output
        TraceEventKind::Stdout => "sandbox.skill.stdout",
        TraceEventKind::Stderr => "sandbox.skill.stderr",

        // Lifecycle
        TraceEventKind::SkillStarted => "sandbox.skill.started",
        TraceEventKind::SkillCompleted => "sandbox.skill.completed",
        TraceEventKind::SkillFailed => "sandbox.skill.failed",

        // Other
        TraceEventKind::DnsResolution => "sandbox.dns.resolve",
        TraceEventKind::ProcessSpawned => "sandbox.process.spawn",
        TraceEventKind::ExitCode => "sandbox.process.exit",
        TraceEventKind::ResourceLimitHit => "sandbox.resource.limit_hit",
    }
}

/// Classify an event as a security-relevant enforcement action.
fn is_enforcement_event(kind: &TraceEventKind) -> bool {
    matches!(
        kind,
        TraceEventKind::NetworkEgressBlocked
            | TraceEventKind::NetworkEgressAllowed
            | TraceEventKind::NetworkPolicyApplied
            | TraceEventKind::EnvVarAccess
            | TraceEventKind::FileBlocked
            | TraceEventKind::SyscallBlocked
            | TraceEventKind::SyscallFiltered
            | TraceEventKind::PolicyViolation
            | TraceEventKind::ResourceLimitHit
    )
}

/// Build OTel attributes from a TraceEvent.
fn event_attributes(event: &TraceEvent) -> Vec<KeyValue> {
    let mut attrs = vec![
        KeyValue::new("sandbox.event.message", event.message.clone()),
        KeyValue::new(
            "sandbox.event.kind",
            format!("{:?}", event.kind),
        ),
    ];

    if is_enforcement_event(&event.kind) {
        attrs.push(KeyValue::new("sandbox.enforcement", true));
    }

    // Add structured data if present
    if let Some(ref data) = event.data {
        if let Some(obj) = data.as_object() {
            for (k, v) in obj {
                let key = format!("sandbox.data.{}", k);
                match v {
                    serde_json::Value::String(s) => {
                        attrs.push(KeyValue::new(key, s.clone()));
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            attrs.push(KeyValue::new(key, i));
                        } else if let Some(f) = n.as_f64() {
                            attrs.push(KeyValue::new(key, f));
                        }
                    }
                    serde_json::Value::Bool(b) => {
                        attrs.push(KeyValue::new(key, *b));
                    }
                    other => {
                        attrs.push(KeyValue::new(key, other.to_string()));
                    }
                }
            }
        }
    }

    attrs
}

/// Export a completed `ExecutionTrace` as OpenTelemetry spans via OTLP.
///
/// Creates a root span for the skill execution, with child spans for each
/// enforcement event. Non-enforcement events (stdout/stderr lines) are added
/// as OTel events on the root span to avoid span explosion.
pub async fn export_trace(trace: &ExecutionTrace) -> Result<()> {
    let provider = init_tracer_provider()?;
    let tracer = provider.tracer("skillsandbox");

    let duration = trace
        .completed_at
        .map(|c| (c - trace.started_at).to_std().unwrap_or_default());

    let violations = trace.policy_violations.len();

    // Create root span
    tracer.in_span("skill_execution", |cx| {
        let span = cx.span();
        span.set_attribute(KeyValue::new("sandbox.skill.name", trace.skill_name.clone()));
        span.set_attribute(KeyValue::new(
            "sandbox.skill.version",
            trace.skill_version.clone(),
        ));
        span.set_attribute(KeyValue::new("sandbox.trace_id", trace.trace_id.clone()));
        span.set_attribute(KeyValue::new(
            "sandbox.violations.count",
            violations as i64,
        ));

        if let Some(exit_code) = trace.exit_code {
            span.set_attribute(KeyValue::new("sandbox.exit_code", exit_code as i64));
        }
        if let Some(d) = duration {
            span.set_attribute(KeyValue::new(
                "sandbox.duration_ms",
                d.as_millis() as i64,
            ));
        }

        if violations > 0 {
            span.set_attribute(KeyValue::new("sandbox.violations.all_prevented", true));
        }

        // Add violation classification to root span if present
        if let Some(ref summary) = trace.violation_summary {
            span.set_attribute(KeyValue::new(
                "sandbox.classification.total_enforcements",
                summary.total_enforcements as i64,
            ));
            span.set_attribute(KeyValue::new(
                "sandbox.classification.max_severity",
                summary.max_severity.clone(),
            ));
            span.set_attribute(KeyValue::new(
                "sandbox.classification.classes",
                summary.classes.join(", "),
            ));
            for cv in &summary.classifications {
                span.set_attribute(KeyValue::new(
                    format!("sandbox.classification.{:?}.count", cv.class).to_lowercase(),
                    cv.count as i64,
                ));
            }
        }

        // Set span status based on exit code
        match trace.exit_code {
            Some(0) => span.set_status(Status::Ok),
            Some(code) => span.set_status(Status::error(format!("exit_code={}", code))),
            None => span.set_status(Status::error("incomplete")),
        }

        // Add events for each trace event
        for event in &trace.events {
            if is_enforcement_event(&event.kind) {
                // Enforcement events become child spans (more visible in trace UIs)
                tracer.in_span(span_name(&event.kind), |inner_cx| {
                    let inner_span = inner_cx.span();
                    for attr in event_attributes(event) {
                        inner_span.set_attribute(attr);
                    }
                    if matches!(
                        event.kind,
                        TraceEventKind::NetworkEgressBlocked
                            | TraceEventKind::PolicyViolation
                            | TraceEventKind::FileBlocked
                            | TraceEventKind::SyscallBlocked
                            | TraceEventKind::ResourceLimitHit
                    ) {
                        inner_span.set_status(Status::error("blocked"));
                    }
                });
            } else {
                // Non-enforcement events become OTel events on root span
                span.add_event(
                    span_name(&event.kind),
                    event_attributes(event),
                );
            }
        }
    });

    // Flush and shutdown — ensures all spans are exported
    provider
        .shutdown()
        .context("Failed to flush OTel spans")?;

    Ok(())
}
