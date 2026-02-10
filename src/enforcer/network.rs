use crate::manifest::{EgressRule, SkillManifest};
use crate::tracer::{TraceEvent, TraceEventKind, Tracer};
use std::net::ToSocketAddrs;
use thiserror::Error;
use tokio::process::Command;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum NetworkEnforcerError {
    #[error("DNS resolution failed for {domain}: {source}")]
    DnsResolution {
        domain: String,
        source: std::io::Error,
    },
    #[error("iptables command failed: {0}")]
    IptablesError(String),
    #[error("network enforcement requires root/CAP_NET_ADMIN")]
    InsufficientPrivileges,
}

/// Resolved egress rule with concrete IP addresses.
#[derive(Debug, Clone)]
pub struct ResolvedEgressRule {
    pub domain: String,
    pub ips: Vec<String>,
    pub ports: Vec<u16>,
    pub protocol: String,
}

/// Manages network egress policy for a sandboxed skill execution.
pub struct NetworkEnforcer {
    chain_name: String,
    resolved_rules: Vec<ResolvedEgressRule>,
    dry_run: bool,
}

impl NetworkEnforcer {
    /// Create a new enforcer from a manifest. Resolves all domains to IPs.
    pub async fn from_manifest(
        manifest: &SkillManifest,
        tracer: &Tracer,
        dry_run: bool,
    ) -> Result<Self, NetworkEnforcerError> {
        // iptables chain names must be < 29 characters.
        // Use a short hash to keep it unique but within the limit.
        let raw_name = manifest
            .skill
            .name
            .to_uppercase()
            .replace('-', "_")
            .replace(' ', "_");
        let chain_name = if raw_name.len() > 20 {
            // Take first 12 chars + 8 char hash to stay under 28
            let hash = &format!("{:08X}", fxhash(&manifest.skill.name));
            format!("SSB_{}_{}", &raw_name[..12], hash)
        } else {
            format!("SSB_{}", raw_name)
        };

        let mut resolved_rules = Vec::new();

        for rule in &manifest.permissions.network.egress {
            match Self::resolve_rule(rule, tracer).await {
                Ok(resolved) => resolved_rules.push(resolved),
                Err(e) => {
                    tracer.record(TraceEvent::now(
                        TraceEventKind::DnsResolution,
                        format!("DNS resolution failed for {}: {}", rule.domain, e),
                    ));
                    // Continue with other rules rather than failing entirely
                    warn!(domain = %rule.domain, error = %e, "DNS resolution failed, skipping rule");
                }
            }
        }

        Ok(Self {
            chain_name,
            resolved_rules,
            dry_run,
        })
    }

    /// Resolve a domain to IP addresses and record it in the trace.
    async fn resolve_rule(
        rule: &EgressRule,
        tracer: &Tracer,
    ) -> Result<ResolvedEgressRule, NetworkEnforcerError> {
        let addr = format!("{}:0", rule.domain);
        let ips: Vec<String> = addr
            .to_socket_addrs()
            .map_err(|e| NetworkEnforcerError::DnsResolution {
                domain: rule.domain.clone(),
                source: e,
            })?
            .map(|a| a.ip().to_string())
            .collect();

        tracer.record(TraceEvent::now(
            TraceEventKind::DnsResolution,
            format!("Resolved {} -> [{}]", rule.domain, ips.join(", ")),
        ));

        info!(
            domain = %rule.domain,
            ips = ?ips,
            ports = ?rule.ports,
            "Resolved egress rule"
        );

        Ok(ResolvedEgressRule {
            domain: rule.domain.clone(),
            ips,
            ports: rule.ports.clone(),
            protocol: rule.protocol.clone(),
        })
    }

    /// Apply iptables rules: allow declared domains, block everything else.
    ///
    /// Strategy:
    ///   1. Create a custom chain for this skill.
    ///   2. Allow loopback + established connections.
    ///   3. For each resolved rule: allow dst IP + port.
    ///   4. Drop everything else (default deny).
    ///   5. Jump from OUTPUT to our chain.
    pub async fn apply(&self, tracer: &Tracer) -> Result<(), NetworkEnforcerError> {
        tracer.record(TraceEvent::now(
            TraceEventKind::NetworkPolicyApplied,
            format!(
                "Applying network policy: {} allowed domains, default-deny egress",
                self.resolved_rules.len()
            ),
        ));

        if self.dry_run {
            self.apply_dry_run(tracer);
            return Ok(());
        }

        // Create chain
        self.iptables(&["-N", &self.chain_name]).await?;

        // Allow loopback
        self.iptables(&["-A", &self.chain_name, "-o", "lo", "-j", "ACCEPT"])
            .await?;

        // Allow established/related connections
        self.iptables(&[
            "-A",
            &self.chain_name,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .await?;

        // Allow DNS (needed for the skill's own DNS resolution if any)
        self.iptables(&[
            "-A",
            &self.chain_name,
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ])
        .await?;

        // Allow each declared egress rule
        for rule in &self.resolved_rules {
            for ip in &rule.ips {
                for port in &rule.ports {
                    self.iptables(&[
                        "-A",
                        &self.chain_name,
                        "-p",
                        &rule.protocol,
                        "-d",
                        ip,
                        "--dport",
                        &port.to_string(),
                        "-j",
                        "ACCEPT",
                    ])
                    .await?;

                    tracer.record(TraceEvent::now(
                        TraceEventKind::NetworkEgressAllowed,
                        format!(
                            "ALLOW {} ({}:{}/{})",
                            rule.domain, ip, port, rule.protocol
                        ),
                    ));
                }
            }
        }

        // Default deny: drop all other outbound traffic
        self.iptables(&["-A", &self.chain_name, "-j", "DROP"])
            .await?;

        tracer.record(TraceEvent::now(
            TraceEventKind::NetworkEgressBlocked,
            "DEFAULT DENY — all undeclared egress blocked".to_string(),
        ));

        // Insert jump from OUTPUT chain
        self.iptables(&["-I", "OUTPUT", "1", "-j", &self.chain_name])
            .await?;

        tracer.record(TraceEvent::now(
            TraceEventKind::NetworkPolicyApplied,
            "iptables rules applied successfully".to_string(),
        ));

        Ok(())
    }

    /// Remove iptables rules (cleanup after execution).
    pub async fn teardown(&self, tracer: &Tracer) -> Result<(), NetworkEnforcerError> {
        if self.dry_run {
            info!("[dry-run] Would remove chain {}", self.chain_name);
            return Ok(());
        }

        // Remove jump
        let _ = self
            .iptables(&["-D", "OUTPUT", "-j", &self.chain_name])
            .await;

        // Flush and delete chain
        let _ = self.iptables(&["-F", &self.chain_name]).await;
        let _ = self.iptables(&["-X", &self.chain_name]).await;

        tracer.record(TraceEvent::now(
            TraceEventKind::NetworkPolicyRemoved,
            format!("Removed iptables chain {}", self.chain_name),
        ));

        Ok(())
    }

    /// Log what rules would be applied without actually calling iptables.
    fn apply_dry_run(&self, tracer: &Tracer) {
        info!("[dry-run] Would create iptables chain: {}", self.chain_name);

        for rule in &self.resolved_rules {
            for ip in &rule.ips {
                for port in &rule.ports {
                    let cmd = format!(
                        "iptables -A {} -p {} -d {} --dport {} -j ACCEPT",
                        self.chain_name, rule.protocol, ip, port
                    );
                    info!("[dry-run] {}", cmd);
                    tracer.record(TraceEvent::now(
                        TraceEventKind::NetworkEgressAllowed,
                        format!(
                            "ALLOW {} ({}:{}/{})",
                            rule.domain, ip, port, rule.protocol
                        ),
                    ));
                }
            }
        }

        info!(
            "[dry-run] iptables -A {} -j DROP  (default deny)",
            self.chain_name
        );
        tracer.record(TraceEvent::now(
            TraceEventKind::NetworkEgressBlocked,
            "DEFAULT DENY — all undeclared egress blocked".to_string(),
        ));
    }

    /// Check whether a domain would be allowed by this policy.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        self.resolved_rules.iter().any(|r| r.domain == domain)
    }

    /// Helper: run an iptables command.
    async fn iptables(&self, args: &[&str]) -> Result<(), NetworkEnforcerError> {
        let output = Command::new("iptables")
            .args(args)
            .output()
            .await
            .map_err(|_| NetworkEnforcerError::InsufficientPrivileges)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(args = ?args, stderr = %stderr, "iptables command failed");
            return Err(NetworkEnforcerError::IptablesError(stderr.to_string()));
        }
        Ok(())
    }
}

/// Simple deterministic hash for chain name uniqueness (no extra crate needed).
fn fxhash(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(0x01000193) ^ (byte as u32);
    }
    hash
}