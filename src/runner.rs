use crate::enforcer::{build_filtered_env, NetworkEnforcer};
use crate::manifest::SkillManifest;
use crate::tracer::{TraceEvent, TraceEventKind, Tracer};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::{error, info};

/// Execute a skill inside the sandbox with all enforcement layers.
pub async fn run_skill(
    skill_dir: &Path,
    dry_run: bool,
    extra_args: &[String],
    trace_output: Option<&Path>,
) -> Result<i32> {
    // 1. Load manifest
    let manifest_path = skill_dir.join("skillsandbox.yaml");
    let manifest = SkillManifest::from_file(&manifest_path)
        .with_context(|| format!("Failed to load manifest from {:?}", manifest_path))?;

    info!(skill = %manifest.skill.name, version = %manifest.skill.version, "Loaded manifest");

    // 2. Create tracer
    let tracer = Tracer::new(&manifest.skill.name, &manifest.skill.version);
    tracer.record(TraceEvent::now(
        TraceEventKind::SkillStarted,
        format!("Starting skill '{}' v{}", manifest.skill.name, manifest.skill.version),
    ));

    // 3. Apply network egress policy
    let net_enforcer = NetworkEnforcer::from_manifest(&manifest, &tracer, dry_run)
        .await
        .context("Failed to set up network enforcer")?;
    net_enforcer
        .apply(&tracer)
        .await
        .context("Failed to apply network policy")?;

    // 4. Build filtered environment
    let env = build_filtered_env(&manifest, &tracer);

    // 5. Spawn the skill process
    let mut cmd_args = manifest.entrypoint.args.clone();
    cmd_args.extend(extra_args.iter().cloned());

    tracer.record(TraceEvent::now(
        TraceEventKind::ProcessSpawned,
        format!(
            "Spawning: {} {}",
            manifest.entrypoint.command,
            cmd_args.join(" ")
        ),
    ));

    let mut child = Command::new(&manifest.entrypoint.command)
        .args(&cmd_args)
        .current_dir(skill_dir)
        .env_clear()
        .envs(&env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "Failed to spawn skill process: {} {:?}",
                manifest.entrypoint.command, cmd_args
            )
        })?;

    // 6. Capture stdout/stderr into trace
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let tracer_out = tracer.clone();
    let stdout_handle = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut collected = String::new();
        while let Ok(Some(line)) = lines.next_line().await {
            tracer_out.record(TraceEvent::now(
                TraceEventKind::Stdout,
                line.clone(),
            ));
            collected.push_str(&line);
            collected.push('\n');
        }
        collected
    });

    let tracer_err = tracer.clone();
    let stderr_handle = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        let mut collected = String::new();
        while let Ok(Some(line)) = lines.next_line().await {
            tracer_err.record(TraceEvent::now(
                TraceEventKind::Stderr,
                line.clone(),
            ));
            collected.push_str(&line);
            collected.push('\n');
        }
        collected
    });

    // 7. Wait with timeout
    let max_duration = Duration::from_secs(manifest.resources.max_runtime_seconds);
    let exit_code = match timeout(max_duration, child.wait()).await {
        Ok(Ok(status)) => status.code().unwrap_or(-1),
        Ok(Err(e)) => {
            error!("Process wait error: {}", e);
            tracer.record(TraceEvent::now(
                TraceEventKind::SkillFailed,
                format!("Process error: {}", e),
            ));
            -1
        }
        Err(_) => {
            // Timeout — kill the process
            let _ = child.kill().await;
            tracer.record(TraceEvent::now(
                TraceEventKind::ResourceLimitHit,
                format!(
                    "Skill exceeded max runtime of {}s — killed",
                    manifest.resources.max_runtime_seconds
                ),
            ));
            -1
        }
    };

    // Wait for output collection to finish
    let stdout_text = stdout_handle.await.unwrap_or_default();
    let stderr_text = stderr_handle.await.unwrap_or_default();

    // 8. Complete trace
    tracer.complete(exit_code);

    // 9. Teardown network policy
    if let Err(e) = net_enforcer.teardown(&tracer).await {
        error!("Failed to teardown network policy: {}", e);
    }

    // 10. Output results
    println!("{}", tracer.summary());

    if !stdout_text.is_empty() {
        println!("\n--- stdout ---\n{}", stdout_text.trim_end());
    }
    if !stderr_text.is_empty() {
        eprintln!("\n--- stderr ---\n{}", stderr_text.trim_end());
    }

    // 11. Write trace
    if let Some(path) = trace_output {
        tracer
            .write_to_file(path)
            .with_context(|| format!("Failed to write trace to {:?}", path))?;
        info!(path = ?path, "Execution trace written");
    } else {
        // Always write to skill_dir/trace.json as default
        let default_path = skill_dir.join("trace.json");
        let _ = tracer.write_to_file(&default_path);
        info!(path = ?default_path, "Execution trace written (default)");
    }

    Ok(exit_code)
}
