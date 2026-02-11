use crate::enforcer::{build_filtered_env, FilesystemEnforcer, NetworkEnforcer};
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

    // 5. Set up filesystem isolation
    let fs_enforcer = FilesystemEnforcer::from_manifest(&manifest, &tracer, dry_run)
        .context("Failed to set up filesystem enforcer")?;
    let fs_setup = fs_enforcer
        .setup(&tracer)
        .context("Failed to set up filesystem isolation")?;

    // Merge env overrides (HOME, TMPDIR, XDG_*) into filtered env
    let mut env = env;
    for (k, v) in &fs_setup.env_overrides {
        env.insert(k.clone(), v.clone());
    }

    // 6. Spawn the skill process
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

    let mut child = if let Some(ref prefix) = fs_setup.mount_prefix {
        // Linux with root: wrap command in unshare -m with bind mounts
        // prefix = ["unshare", "-m", "--", "sh", "-c", "mount_cmds"]
        // We append "&& exec <real_command> <args>" to the shell script
        let real_cmd = format!(
            "{} && exec {} {}",
            prefix.last().unwrap_or(&String::new()),
            shell_escape(&manifest.entrypoint.command),
            cmd_args.iter().map(|a| shell_escape(a)).collect::<Vec<_>>().join(" ")
        );

        let mut full_prefix = prefix[..prefix.len() - 1].to_vec();
        full_prefix.push(real_cmd);

        Command::new(&full_prefix[0])
            .args(&full_prefix[1..])
            .current_dir(skill_dir)
            .env_clear()
            .envs(&env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "Failed to spawn skill process with mount namespace: {:?}",
                    full_prefix
                )
            })?
    } else {
        // No mount namespace: env-based isolation only
        Command::new(&manifest.entrypoint.command)
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
            })?
    };

    // 7. Capture stdout/stderr into trace
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

    // 8. Wait with timeout
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

    // 9. Complete trace
    tracer.complete(exit_code);

    // 10. Teardown network policy
    if let Err(e) = net_enforcer.teardown(&tracer).await {
        error!("Failed to teardown network policy: {}", e);
    }

    // 11. Audit filesystem — check what the skill wrote
    fs_enforcer.audit_scratch(&tracer);

    // 12. Output results
    println!("{}", tracer.summary());

    if !stdout_text.is_empty() {
        println!("\n--- stdout ---\n{}", stdout_text.trim_end());
    }
    if !stderr_text.is_empty() {
        eprintln!("\n--- stderr ---\n{}", stderr_text.trim_end());
    }

    // 13. Write trace
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

/// Escape a string for safe use in a shell command.
fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/') {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
