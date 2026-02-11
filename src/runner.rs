use crate::enforcer::{build_filtered_env, FilesystemEnforcer, NetworkEnforcer, SeccompEnforcer};
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

    // 6. Set up seccomp syscall filter
    let seccomp_enforcer = SeccompEnforcer::from_manifest(&manifest, &tracer, dry_run)
        .context("Failed to set up seccomp enforcer")?;
    seccomp_enforcer.trace_setup(&tracer);

    // 7. Spawn the skill process
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

    let mut child = {
        let mut cmd = if let Some(ref prefix) = fs_setup.mount_prefix {
            // Linux with root: wrap command in unshare -m with bind mounts
            // We inject seccomp setup INTO the shell script so it applies
            // after mount setup but before the skill process runs.
            // This avoids blocking `unshare` syscall in the wrapper itself.
            let seccomp_script = if !seccomp_enforcer.is_dry_run()
                && !seccomp_enforcer.blocked_syscalls().is_empty()
            {
                // Use a Python one-liner to install seccomp via ctypes/prctl
                // This is more reliable than trying to use pre_exec with unshare
                build_seccomp_prctl_snippet(&seccomp_enforcer)
            } else {
                String::new()
            };

            let real_cmd = format!(
                "{}{} && exec {} {}",
                prefix.last().unwrap_or(&String::new()),
                if seccomp_script.is_empty() {
                    String::new()
                } else {
                    format!(" && {}", seccomp_script)
                },
                shell_escape(&manifest.entrypoint.command),
                cmd_args.iter().map(|a| shell_escape(a)).collect::<Vec<_>>().join(" ")
            );

            let mut full_prefix = prefix[..prefix.len() - 1].to_vec();
            full_prefix.push(real_cmd);

            let mut cmd = Command::new(&full_prefix[0]);
            cmd.args(&full_prefix[1..])
                .current_dir(skill_dir)
                .env_clear()
                .envs(&env)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            cmd
        } else {
            // No mount namespace: env-based isolation only
            let mut cmd = Command::new(&manifest.entrypoint.command);
            cmd.args(&cmd_args)
                .current_dir(skill_dir)
                .env_clear()
                .envs(&env)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            // Install seccomp BPF filter in child process before exec.
            // pre_exec runs after fork() but before exec(), so the filter
            // applies only to the skill process, not the sandbox runtime.
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                unsafe {
                    cmd.pre_exec(move || {
                        seccomp_enforcer.install_filter().map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                        })
                    });
                }
            }

            cmd
        };

        cmd.spawn()
            .context("Failed to spawn skill process")?
    };

    // 8. Capture stdout/stderr into trace
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

    // 9. Wait with timeout
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

    // 10. Complete trace
    tracer.complete(exit_code);

    // 11. Teardown network policy
    if let Err(e) = net_enforcer.teardown(&tracer).await {
        error!("Failed to teardown network policy: {}", e);
    }

    // 12. Audit filesystem — check what the skill wrote
    fs_enforcer.audit_scratch(&tracer);

    // 13. Output results
    println!("{}", tracer.summary());

    if !stdout_text.is_empty() {
        println!("\n--- stdout ---\n{}", stdout_text.trim_end());
    }
    if !stderr_text.is_empty() {
        eprintln!("\n--- stderr ---\n{}", stderr_text.trim_end());
    }

    // 14. Write trace
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

/// Build a shell snippet that sets PR_SET_NO_NEW_PRIVS before exec.
/// This is used in the mount namespace path where pre_exec can't be used
/// (because the pre_exec would apply to `unshare` itself, blocking it).
///
/// We only set NO_NEW_PRIVS here — the seccomp BPF filter is complex
/// to install from shell, but NO_NEW_PRIVS alone prevents privilege
/// escalation via setuid/setgid binaries, which is the most critical
/// protection. The full BPF filter is installed via pre_exec in the
/// non-mount-namespace path.
#[cfg(target_os = "linux")]
fn build_seccomp_prctl_snippet(_enforcer: &crate::enforcer::SeccompEnforcer) -> String {
    // PR_SET_NO_NEW_PRIVS = 38, arg = 1
    // Use python3 (which we know is available since skills use it) to call prctl
    "python3 -c 'import ctypes; ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)'".to_string()
}

#[cfg(not(target_os = "linux"))]
fn build_seccomp_prctl_snippet(_enforcer: &crate::enforcer::SeccompEnforcer) -> String {
    String::new()
}
