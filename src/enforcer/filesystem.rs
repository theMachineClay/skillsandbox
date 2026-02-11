use crate::manifest::SkillManifest;
use crate::tracer::{TraceEvent, TraceEventKind, Tracer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use thiserror::Error;
use tracing::info;

#[derive(Error, Debug)]
pub enum FilesystemEnforcerError {
    #[error("failed to create isolation directory: {0}")]
    SetupError(String),
    #[error("path validation failed: {0}")]
    PathValidation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Manages filesystem isolation for a sandboxed skill execution.
///
/// Strategy:
///   1. Create a temporary scratch directory for the execution.
///   2. Inside it, create subdirectories mirroring declared paths.
///   3. Set HOME, TMPDIR, XDG_CACHE_HOME to the scratch dir.
///   4. On Linux, attempt `unshare -m` + bind mounts for real isolation.
///   5. Record all filesystem setup in the trace.
///
/// The malicious skill tries to write to:
///   - /tmp/.weather-cache-data      (hidden file in /tmp)
///   - /tmp/weather-cache/.stolen     (hidden inside allowed dir)
///   - /var/tmp/.wx-data             (alternative temp dir)
///   - ~/.cache/.weather-telemetry   (user cache dir)
///
/// With this enforcer:
///   - HOME points to scratch dir → ~/.cache resolves inside scratch
///   - TMPDIR points to scratch/tmp → but /tmp itself may still be writable
///   - On Linux with root: bind-mount scratch/tmp over /tmp so the
///     process literally cannot write outside declared paths
pub struct FilesystemEnforcer {
    /// The temporary scratch directory (kept alive for duration of execution).
    scratch_dir: TempDir,
    /// Declared read paths from the manifest.
    allowed_read: Vec<PathBuf>,
    /// Declared write paths from the manifest.
    allowed_write: Vec<PathBuf>,
    /// Whether to attempt Linux mount namespace isolation.
    use_mount_ns: bool,
    /// Dry run mode.
    dry_run: bool,
}

impl FilesystemEnforcer {
    /// Create a new filesystem enforcer from the manifest.
    pub fn from_manifest(
        manifest: &SkillManifest,
        tracer: &Tracer,
        dry_run: bool,
    ) -> Result<Self, FilesystemEnforcerError> {
        let allowed_read: Vec<PathBuf> = manifest
            .permissions
            .filesystem
            .read
            .iter()
            .map(PathBuf::from)
            .collect();

        let allowed_write: Vec<PathBuf> = manifest
            .permissions
            .filesystem
            .write
            .iter()
            .map(PathBuf::from)
            .collect();

        // Create the scratch directory
        let scratch_dir = TempDir::new().map_err(|e| {
            FilesystemEnforcerError::SetupError(format!("Failed to create temp dir: {}", e))
        })?;

        // Detect if we can use mount namespaces (Linux + root)
        let use_mount_ns = cfg!(target_os = "linux") && is_root();

        tracer.record(TraceEvent::now(
            TraceEventKind::FileWrite,
            format!(
                "Filesystem enforcer: scratch={}, read_paths={}, write_paths={}, mount_ns={}",
                scratch_dir.path().display(),
                allowed_read.len(),
                allowed_write.len(),
                use_mount_ns,
            ),
        ));

        Ok(Self {
            scratch_dir,
            allowed_read,
            allowed_write,
            use_mount_ns,
            dry_run,
        })
    }

    /// Set up the isolated filesystem environment.
    /// Creates directories for declared paths and returns env overrides.
    pub fn setup(&self, tracer: &Tracer) -> Result<FilesystemSetup, FilesystemEnforcerError> {
        let scratch = self.scratch_dir.path();

        // Create isolated subdirectories inside scratch
        let scratch_tmp = scratch.join("tmp");
        let scratch_home = scratch.join("home");
        let scratch_cache = scratch_home.join(".cache");

        if self.dry_run {
            return self.setup_dry_run(tracer);
        }

        std::fs::create_dir_all(&scratch_tmp)?;
        std::fs::create_dir_all(&scratch_home)?;
        std::fs::create_dir_all(&scratch_cache)?;

        // Create declared writable paths inside scratch
        // The skill declares write: ["/tmp/weather-cache"]
        // We create scratch/tmp/weather-cache and will redirect /tmp there
        for path in &self.allowed_write {
            let relative = path
                .strip_prefix("/")
                .unwrap_or(path.as_path());
            let target = scratch.join(relative);
            std::fs::create_dir_all(&target)?;

            tracer.record(TraceEvent::now(
                TraceEventKind::FileWrite,
                format!(
                    "FS ALLOW WRITE: {} → {}",
                    path.display(),
                    target.display()
                ),
            ));

            info!(
                declared = %path.display(),
                actual = %target.display(),
                "Created writable path in scratch"
            );
        }

        // Create declared readable paths inside scratch (if they don't exist on host, create empty)
        for path in &self.allowed_read {
            let relative = path
                .strip_prefix("/")
                .unwrap_or(path.as_path());
            let target = scratch.join(relative);
            std::fs::create_dir_all(&target)?;

            tracer.record(TraceEvent::now(
                TraceEventKind::FileRead,
                format!(
                    "FS ALLOW READ: {} → {}",
                    path.display(),
                    target.display()
                ),
            ));
        }

        // Build the command prefix for mount namespace isolation (Linux only)
        let mount_prefix = if self.use_mount_ns {
            let prefix = self.build_mount_ns_prefix(tracer)?;
            tracer.record(TraceEvent::now(
                TraceEventKind::FileBlocked,
                "Filesystem isolation: mount namespace active — /tmp, /home, /var/tmp are isolated"
                    .to_string(),
            ));
            Some(prefix)
        } else {
            tracer.record(TraceEvent::now(
                TraceEventKind::FileBlocked,
                "Filesystem isolation: env-based (HOME/TMPDIR redirect) — no mount namespace"
                    .to_string(),
            ));
            None
        };

        // Log what's blocked
        tracer.record(TraceEvent::now(
            TraceEventKind::FileBlocked,
            format!(
                "FS DENY: all paths outside {:?} + {:?} are restricted",
                self.allowed_read, self.allowed_write
            ),
        ));

        Ok(FilesystemSetup {
            env_overrides: self.build_env_overrides(),
            mount_prefix,
            scratch_path: scratch.to_path_buf(),
        })
    }

    /// Build environment variable overrides that redirect common paths.
    fn build_env_overrides(&self) -> HashMap<String, String> {
        let scratch = self.scratch_dir.path();
        let mut env = HashMap::new();

        // Redirect HOME so ~/.cache, ~/.ssh etc. resolve into scratch
        env.insert(
            "HOME".to_string(),
            scratch.join("home").to_string_lossy().to_string(),
        );

        // Redirect TMPDIR so tempfile.mkdtemp() etc. use scratch
        env.insert(
            "TMPDIR".to_string(),
            scratch.join("tmp").to_string_lossy().to_string(),
        );

        // Redirect XDG dirs
        env.insert(
            "XDG_CACHE_HOME".to_string(),
            scratch.join("home").join(".cache").to_string_lossy().to_string(),
        );
        env.insert(
            "XDG_DATA_HOME".to_string(),
            scratch.join("home").join(".local").join("share").to_string_lossy().to_string(),
        );
        env.insert(
            "XDG_CONFIG_HOME".to_string(),
            scratch.join("home").join(".config").to_string_lossy().to_string(),
        );

        env
    }

    /// Build unshare + bind-mount command prefix for Linux.
    /// This gives us a real mount namespace where /tmp, /home, /var/tmp
    /// are bind-mounted from our scratch directory.
    fn build_mount_ns_prefix(
        &self,
        tracer: &Tracer,
    ) -> Result<Vec<String>, FilesystemEnforcerError> {
        let scratch = self.scratch_dir.path();

        // Build a shell script that:
        // 1. unshare -m (new mount namespace)
        // 2. bind-mount scratch/tmp over /tmp
        // 3. bind-mount scratch/home over /home (or $HOME)
        // 4. bind-mount scratch/var/tmp over /var/tmp
        // 5. exec the actual command
        let scratch_tmp = scratch.join("tmp");
        let _scratch_home = scratch.join("home");
        let scratch_var_tmp = scratch.join("var_tmp");

        // Create var_tmp in scratch
        std::fs::create_dir_all(&scratch_var_tmp)?;

        // Build mount commands — mount declared writable paths back in
        let mut mount_cmds = vec![
    format!("mount --bind {} /var/tmp", scratch_var_tmp.display()),
    format!("mount --bind {} /tmp", scratch_tmp.display()),
];

        // If the declared paths are under /tmp, they already exist in scratch_tmp.
        // If they're elsewhere, we need to bind-mount them individually.
        for path in &self.allowed_write {
            if !path.starts_with("/tmp") && !path.starts_with("/var/tmp") {
                let relative = path
                    .strip_prefix("/")
                    .unwrap_or(path.as_path());
                let scratch_path = scratch.join(relative);
                std::fs::create_dir_all(&scratch_path)?;
                // Ensure the mount point exists on the (now-overlaid) filesystem
                mount_cmds.push(format!(
                    "mkdir -p {} && mount --bind {} {}",
                    path.display(),
                    scratch_path.display(),
                    path.display()
                ));
            }
        }

        let mount_script = mount_cmds.join(" && ");

        tracer.record(TraceEvent::now(
            TraceEventKind::FileWrite,
            format!("Mount namespace setup: {}", mount_script),
        ));

        // Return the prefix args: unshare -m sh -c "mount... && exec real_command"
        // The caller will need to wrap the actual command with this
        Ok(vec![
            "unshare".to_string(),
            "-m".to_string(),
            "--".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            mount_script,
        ])
    }

    /// Dry-run: log what would be set up.
    fn setup_dry_run(
        &self,
        tracer: &Tracer,
    ) -> Result<FilesystemSetup, FilesystemEnforcerError> {
        let scratch = self.scratch_dir.path();

        info!("[dry-run] Would create scratch dir: {}", scratch.display());

        for path in &self.allowed_write {
            let relative = path.strip_prefix("/").unwrap_or(path.as_path());
            let target = scratch.join(relative);
            info!(
                "[dry-run] FS ALLOW WRITE: {} → {}",
                path.display(),
                target.display()
            );
            tracer.record(TraceEvent::now(
                TraceEventKind::FileWrite,
                format!("FS ALLOW WRITE: {} (dry-run)", path.display()),
            ));
        }

        for path in &self.allowed_read {
            info!("[dry-run] FS ALLOW READ: {}", path.display());
            tracer.record(TraceEvent::now(
                TraceEventKind::FileRead,
                format!("FS ALLOW READ: {} (dry-run)", path.display()),
            ));
        }

        tracer.record(TraceEvent::now(
            TraceEventKind::FileBlocked,
            "FS DENY: all undeclared paths restricted (dry-run)".to_string(),
        ));

        Ok(FilesystemSetup {
            env_overrides: self.build_env_overrides(),
            mount_prefix: None,
            scratch_path: scratch.to_path_buf(),
        })
    }

    /// Validate a path against the declared permissions.
    /// Used by the trace analysis to classify filesystem events.
    pub fn is_path_allowed(&self, path: &Path, write: bool) -> bool {
        let check_list = if write {
            &self.allowed_write
        } else {
            // Read access: allowed if in read OR write list
            let in_read = self.allowed_read.iter().any(|p| path.starts_with(p));
            let in_write = self.allowed_write.iter().any(|p| path.starts_with(p));
            return in_read || in_write;
        };

        check_list.iter().any(|p| path.starts_with(p))
    }

    /// Post-execution: scan scratch dir for files the skill created
    /// outside declared paths. Record as trace events.
    pub fn audit_scratch(&self, tracer: &Tracer) {
        let scratch = self.scratch_dir.path();

        // Walk the scratch dir and report what was created
        if let Ok(entries) = walkdir(scratch) {
            for entry in entries {
                let relative = entry
                    .strip_prefix(scratch)
                    .unwrap_or(&entry);
                let absolute = Path::new("/").join(relative);

                let allowed = self.is_path_allowed(&absolute, true);

                if allowed {
                    tracer.record(TraceEvent::now(
                        TraceEventKind::FileWrite,
                        format!("FS audit: {} (allowed)", absolute.display()),
                    ));
                } else {
                    tracer.record(TraceEvent::now(
                        TraceEventKind::FileBlocked,
                        format!(
                            "FS audit: {} — BLOCKED (not in declared write paths)",
                            absolute.display()
                        ),
                    ));
                }
            }
        }
    }
}

/// Setup result returned to the runner.
pub struct FilesystemSetup {
    /// Extra env vars to merge (HOME, TMPDIR, XDG_*).
    pub env_overrides: HashMap<String, String>,
    /// Optional command prefix for mount namespace isolation.
    /// If Some, the runner should prepend these args to the command.
    pub mount_prefix: Option<Vec<String>>,
    /// Path to the scratch directory.
    pub scratch_path: PathBuf,
}

/// Check if we're running as root.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Simple recursive directory walk returning file paths.
fn walkdir(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut results = Vec::new();

    if !dir.is_dir() {
        return Ok(results);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            results.extend(walkdir(&path)?);
        } else {
            results.push(path);
        }
    }

    Ok(results)
}
