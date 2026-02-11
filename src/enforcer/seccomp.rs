use crate::manifest::SkillManifest;
use crate::tracer::{TraceEvent, TraceEventKind, Tracer};
use thiserror::Error;
use tracing::info;

#[derive(Error, Debug)]
pub enum SeccompError {
    #[error("seccomp setup failed: {0}")]
    Setup(String),
}

// ---------------------------------------------------------------------------
// Syscall profile definitions
// ---------------------------------------------------------------------------

/// A named seccomp profile that maps to a set of blocked syscalls.
/// Profiles are ordered from most permissive to most restrictive:
///
///   - "permissive":  Log only, block nothing (useful for debugging)
///   - "default":     Block dangerous syscalls (ptrace, mount, reboot, etc.)
///   - "strict":      Block default + raw sockets, module loading, BPF
///   - "paranoid":    Block strict + personality, ioctl, etc.
///
/// The default profile mirrors Docker's default seccomp policy:
/// block ~44 syscalls known to be unnecessary for most workloads and
/// that represent privilege escalation or container escape vectors.
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    pub name: String,
    pub blocked_syscalls: Vec<&'static str>,
    pub description: String,
}

impl SeccompProfile {
    /// The "permissive" profile — logs what would be blocked but allows all.
    pub fn permissive() -> Self {
        Self {
            name: "permissive".to_string(),
            blocked_syscalls: vec![],
            description: "No syscalls blocked (log only)".to_string(),
        }
    }

    /// The "default" profile — blocks dangerous syscalls.
    /// Modeled after Docker's default seccomp profile.
    /// These syscalls are almost never needed by application code and
    /// represent privilege escalation or host escape vectors.
    pub fn default_profile() -> Self {
        Self {
            name: "default".to_string(),
            blocked_syscalls: vec![
                // Privilege escalation
                "ptrace",           // Process tracing — debugger/escape vector
                "personality",      // Change execution domain
                "setns",            // Enter another namespace — container escape
                "unshare",          // Create new namespace (we use this for fs, but child shouldn't)

                // Kernel module / BPF
                "init_module",      // Load kernel module
                "finit_module",     // Load kernel module from fd
                "delete_module",    // Unload kernel module
                "create_module",    // Create kernel module (obsolete)

                // System control
                "reboot",           // Reboot the system
                "kexec_load",       // Load new kernel
                "kexec_file_load",  // Load new kernel from file
                "swapon",           // Enable swap
                "swapoff",          // Disable swap
                "acct",             // Process accounting
                "pivot_root",       // Change root filesystem
                "chroot",           // Change root directory
                "syslog",           // Read/control kernel message buffer

                // Dangerous I/O
                "iopl",             // Change I/O privilege level
                "ioperm",           // Set port I/O permissions
                "mount",            // Mount filesystem
                "umount2",          // Unmount filesystem

                // Keyring (credential storage)
                "add_key",          // Add key to kernel keyring
                "request_key",      // Request key from kernel keyring
                "keyctl",           // Keyring manipulation

                // Namespace manipulation
                "clone3",           // Create child process with new ns (recent)
                "userfaultfd",      // Userfaultfd — used in exploits

                // Clock manipulation
                "clock_settime",    // Set system clock
                "settimeofday",     // Set time of day
                "adjtimex",         // Tune kernel clock

                // Virtualization / VM
                "vm86",             // Enter VM86 mode (x86 only)
                "vm86old",          // Old VM86 (x86 only)
                "modify_ldt",       // Modify local descriptor table

                // Resource limits that could affect host
                "setdomainname",    // Set NIS domain name
                "sethostname",      // Set hostname
                "nfsservctl",       // NFS server control (obsolete)

                // Rarely needed, high risk
                "lookup_dcookie",   // Profiling — dcookies
                "perf_event_open",  // Performance monitoring — info leak
                "bpf",              // BPF operations — powerful, dangerous
                "move_pages",       // NUMA page migration
                "mbind",            // NUMA memory policy (can be abused)
                "get_mempolicy",    // NUMA memory policy query
                "set_mempolicy",    // NUMA memory policy set
            ],
            description: "Block dangerous syscalls (Docker-equivalent default)".to_string(),
        }
    }

    /// The "strict" profile — blocks default + networking/raw sockets.
    pub fn strict() -> Self {
        let mut blocked = Self::default_profile().blocked_syscalls;
        blocked.extend_from_slice(&[
            // Raw network access
            "socket",           // Blocked: we control network via iptables, not syscalls
                                // Note: this would break most programs. Only for ultra-locked-down
                                // skills that should have NO network access at all.

            // Process control
            "kill",             // Send signals to other processes
            "tkill",            // Thread-directed kill
            "tgkill",           // Thread-group-directed kill

            // More namespace ops
            "clone",            // Fork with namespace flags
        ]);
        Self {
            name: "strict".to_string(),
            blocked_syscalls: blocked,
            description: "Block default + raw sockets + signals + clone".to_string(),
        }
    }

    /// Look up a profile by name.
    pub fn from_name(name: &str) -> Result<Self, SeccompError> {
        match name {
            "permissive" => Ok(Self::permissive()),
            "default" => Ok(Self::default_profile()),
            "strict" => Ok(Self::strict()),
            other => Err(SeccompError::Setup(format!(
                "Unknown seccomp profile: '{}'. Valid profiles: permissive, default, strict",
                other
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// SeccompEnforcer — builds and applies the BPF filter
// ---------------------------------------------------------------------------

pub struct SeccompEnforcer {
    profile: SeccompProfile,
    dry_run: bool,
}

impl SeccompEnforcer {
    /// Create a seccomp enforcer from the manifest.
    pub fn from_manifest(
        manifest: &SkillManifest,
        tracer: &Tracer,
        dry_run: bool,
    ) -> Result<Self, SeccompError> {
        let profile_name = &manifest.permissions.syscalls.profile;
        let profile = SeccompProfile::from_name(profile_name)?;

        tracer.record(TraceEvent::now(
            TraceEventKind::SyscallFiltered,
            format!(
                "Seccomp profile '{}': {} syscalls will be blocked — {}",
                profile.name,
                profile.blocked_syscalls.len(),
                profile.description,
            ),
        ));

        info!(
            profile = %profile.name,
            blocked_count = profile.blocked_syscalls.len(),
            "Seccomp profile loaded"
        );

        Ok(Self { profile, dry_run })
    }

    /// Returns the list of blocked syscall names for logging/tracing.
    pub fn blocked_syscalls(&self) -> &[&str] {
        &self.profile.blocked_syscalls
    }

    /// Returns the profile name.
    pub fn profile_name(&self) -> &str {
        &self.profile.name
    }

    /// Returns whether this is a dry run.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Log the seccomp setup to the tracer.
    pub fn trace_setup(&self, tracer: &Tracer) {
        if self.dry_run {
            tracer.record(TraceEvent::now(
                TraceEventKind::SyscallFiltered,
                format!(
                    "[dry-run] Would block {} syscalls: {:?}",
                    self.profile.blocked_syscalls.len(),
                    self.profile.blocked_syscalls,
                ),
            ));
            return;
        }

        if self.profile.blocked_syscalls.is_empty() {
            tracer.record(TraceEvent::now(
                TraceEventKind::SyscallFiltered,
                "Seccomp: permissive mode — no syscalls blocked".to_string(),
            ));
            return;
        }

        tracer.record(TraceEvent::now(
            TraceEventKind::SyscallFiltered,
            format!(
                "Seccomp: blocking {} syscalls via BPF filter",
                self.profile.blocked_syscalls.len(),
            ),
        ));

        // Log each blocked syscall for the audit trail
        for syscall in &self.profile.blocked_syscalls {
            tracer.record(TraceEvent::now(
                TraceEventKind::SyscallFiltered,
                format!("DENY syscall: {}", syscall),
            ));
        }
    }

    /// Build the seccomp BPF filter and install it on the current process.
    /// This MUST be called from within a pre_exec hook (i.e., after fork,
    /// before exec) so that the filter applies to the child process only.
    ///
    /// On non-Linux platforms, this is a no-op.
    /// In dry-run mode, this logs but does not install.
    #[cfg(target_os = "linux")]
    pub fn install_filter(&self) -> Result<(), SeccompError> {
        use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
        use std::convert::TryInto;

        if self.dry_run || self.profile.blocked_syscalls.is_empty() {
            return Ok(());
        }

        // Detect architecture at compile time
        #[cfg(target_arch = "x86_64")]
        let arch = seccompiler::TargetArch::x86_64;
        #[cfg(target_arch = "aarch64")]
        let arch = seccompiler::TargetArch::aarch64;

        let mut rules: Vec<(i64, Vec<SeccompRule>)> = Vec::new();

        for syscall_name in &self.profile.blocked_syscalls {
            if let Some(nr) = syscall_number(syscall_name) {
                if nr < 0 {
                    continue; // Syscall doesn't exist on this arch
                }
                rules.push((nr, vec![SeccompRule::new(vec![]).map_err(|e| {
                    SeccompError::Setup(format!("Failed to create rule for {}: {}", syscall_name, e))
                })?]));
            }
        }

        let filter = SeccompFilter::new(
            rules.into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Errno(1),       // Blocked syscalls: EPERM
            arch,
        )
        .map_err(|e| SeccompError::Setup(format!("Failed to build seccomp filter: {}", e)))?;

        let bpf_prog: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| {
                SeccompError::Setup(format!("Failed to compile BPF program: {}", e))
            })?;

        // The kernel requires NO_NEW_PRIVS to be set before installing
        // a seccomp filter (unless the process has CAP_SYS_ADMIN, but that
        // may not be inherited reliably through unshare/pre_exec).
        // This is a security best practice anyway: it prevents the skill
        // process from gaining new privileges via setuid/setgid binaries.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(SeccompError::Setup(
                "prctl(PR_SET_NO_NEW_PRIVS) failed".to_string(),
            ));
        }

        seccompiler::apply_filter(&bpf_prog)
            .map_err(|e| SeccompError::Setup(format!("Failed to install seccomp filter: {}", e)))?;

        Ok(())
    }

    /// Non-Linux: no-op.
    #[cfg(not(target_os = "linux"))]
    pub fn install_filter(&self) -> Result<(), SeccompError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Syscall name → number mapping (Linux x86_64)
// ---------------------------------------------------------------------------

/// Map syscall names to numbers for the current architecture.
/// Reference:
///   x86_64:  /usr/include/x86_64-linux-gnu/asm/unistd_64.h
///   aarch64: /usr/include/aarch64-linux-gnu/asm/unistd.h (uses __NR3264 base)
#[cfg(target_os = "linux")]
fn syscall_number(name: &str) -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        Some(match name {
            "ptrace"            => 101,
            "personality"       => 135,
            "setns"             => 308,
            "unshare"           => 272,
            "init_module"       => 175,
            "finit_module"      => 313,
            "delete_module"     => 176,
            "create_module"     => 174,
            "reboot"            => 169,
            "kexec_load"        => 246,
            "kexec_file_load"   => 320,
            "swapon"            => 167,
            "swapoff"           => 168,
            "acct"              => 163,
            "pivot_root"        => 155,
            "chroot"            => 161,
            "syslog"            => 103,
            "iopl"              => 172,
            "ioperm"            => 173,
            "mount"             => 165,
            "umount2"           => 166,
            "add_key"           => 248,
            "request_key"       => 249,
            "keyctl"            => 250,
            "clone3"            => 435,
            "userfaultfd"       => 323,
            "clock_settime"     => 227,
            "settimeofday"      => 164,
            "adjtimex"          => 159,
            "vm86"              => -1, // Not on x86_64
            "vm86old"           => -1, // Not on x86_64
            "modify_ldt"        => 154,
            "setdomainname"     => 171,
            "sethostname"       => 170,
            "nfsservctl"        => 180,
            "lookup_dcookie"    => 212,
            "perf_event_open"   => 298,
            "bpf"               => 321,
            "move_pages"        => 279,
            "mbind"             => 237,
            "get_mempolicy"     => 239,
            "set_mempolicy"     => 238,
            // Strict profile additions
            "socket"            => 41,
            "kill"              => 62,
            "tkill"             => 200,
            "tgkill"            => 234,
            "clone"             => 56,
            _ => return None,
        })
    }

    #[cfg(target_arch = "aarch64")]
    {
        Some(match name {
            "ptrace"            => 117,
            "personality"       => 92,
            "setns"             => 268,
            "unshare"           => 97,
            "init_module"       => 105,
            "finit_module"      => 273,
            "delete_module"     => 106,
            "create_module"     => -1, // Not on aarch64
            "reboot"            => 142,
            "kexec_load"        => 104,
            "kexec_file_load"   => 294,
            "swapon"            => 224,
            "swapoff"           => 225,
            "acct"              => 89,
            "pivot_root"        => 41,
            "chroot"            => 51,
            "syslog"            => 116,
            "iopl"              => -1, // x86 only
            "ioperm"            => -1, // x86 only
            "mount"             => 21,
            "umount2"           => 39,
            "add_key"           => 217,
            "request_key"       => 218,
            "keyctl"            => 219,
            "clone3"            => 435,
            "userfaultfd"       => 282,
            "clock_settime"     => 112,
            "settimeofday"      => 170,
            "adjtimex"          => 171,
            "vm86"              => -1, // x86 only
            "vm86old"           => -1, // x86 only
            "modify_ldt"        => -1, // x86 only
            "setdomainname"     => 162,
            "sethostname"       => 161,
            "nfsservctl"        => -1, // Removed on aarch64
            "lookup_dcookie"    => -1, // Not on aarch64
            "perf_event_open"   => 241,
            "bpf"               => 280,
            "move_pages"        => 239,
            "mbind"             => 235,
            "get_mempolicy"     => 236,
            "set_mempolicy"     => 237,
            // Strict profile additions
            "socket"            => 198,
            "kill"              => 129,
            "tkill"             => 130,
            "tgkill"            => 131,
            "clone"             => 220,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_has_dangerous_syscalls() {
        let profile = SeccompProfile::default_profile();
        assert!(profile.blocked_syscalls.contains(&"ptrace"));
        assert!(profile.blocked_syscalls.contains(&"mount"));
        assert!(profile.blocked_syscalls.contains(&"reboot"));
        assert!(profile.blocked_syscalls.contains(&"kexec_load"));
        assert!(profile.blocked_syscalls.contains(&"bpf"));
        assert!(!profile.blocked_syscalls.contains(&"read"));
        assert!(!profile.blocked_syscalls.contains(&"write"));
        assert!(!profile.blocked_syscalls.contains(&"open"));
    }

    #[test]
    fn strict_profile_extends_default() {
        let default = SeccompProfile::default_profile();
        let strict = SeccompProfile::strict();
        assert!(strict.blocked_syscalls.len() > default.blocked_syscalls.len());
        assert!(strict.blocked_syscalls.contains(&"socket"));
        assert!(strict.blocked_syscalls.contains(&"kill"));
    }

    #[test]
    fn permissive_blocks_nothing() {
        let profile = SeccompProfile::permissive();
        assert!(profile.blocked_syscalls.is_empty());
    }

    #[test]
    fn unknown_profile_errors() {
        let result = SeccompProfile::from_name("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn valid_profiles_load() {
        assert!(SeccompProfile::from_name("permissive").is_ok());
        assert!(SeccompProfile::from_name("default").is_ok());
        assert!(SeccompProfile::from_name("strict").is_ok());
    }
}
