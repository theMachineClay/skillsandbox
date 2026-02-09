use crate::manifest::SkillManifest;
use crate::tracer::{TraceEvent, TraceEventKind, Tracer};
use std::collections::HashMap;
use tracing::info;

/// Build a filtered environment map for the sandboxed process.
/// Only env vars declared in `permissions.env_vars.allow` are passed through.
/// All others are stripped — the skill never sees them.
pub fn build_filtered_env(
    manifest: &SkillManifest,
    tracer: &Tracer,
) -> HashMap<String, String> {
    let allowed: Vec<&str> = manifest.allowed_env_vars();
    let mut filtered = HashMap::new();
    let mut blocked_count = 0u32;

    for (key, value) in std::env::vars() {
        if allowed.contains(&key.as_str()) {
            filtered.insert(key.clone(), value);
            tracer.record(TraceEvent::now(
                TraceEventKind::EnvVarAccess,
                format!("ENV allowed: {}", key),
            ));
        } else {
            blocked_count += 1;
        }
    }

    tracer.record(TraceEvent::now(
        TraceEventKind::EnvVarAccess,
        format!(
            "Environment filtered: {} vars allowed, {} vars stripped",
            filtered.len(),
            blocked_count
        ),
    ));

    info!(
        allowed = filtered.len(),
        blocked = blocked_count,
        "Environment variables filtered"
    );

    filtered
}
