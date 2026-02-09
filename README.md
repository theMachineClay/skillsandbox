# SkillSandbox

**Capability-based sandbox runtime for AI agent skills.**

Skills declare what they need. The runtime enforces it. Every execution produces a structured audit trail.

## Why

A [credential stealer was discovered on ClawdHub](https://github.com/anthropics/knowledge-work-plugins) disguised as a weather skill — it read API keys and POSTed them to an external server. The community proposed code signing. Code signing doesn't fix this: a legitimately signed skill can still be compromised after publication.

**Don't trust the code. Constrain what it can do.**

## How It Works

```
skillsandbox.yaml          Runtime Enforcement         Audit Trail
┌─────────────────┐       ┌──────────────────────┐    ┌──────────────┐
│ permissions:     │──────▶│ Network: iptables     │───▶│ trace.json   │
│   network:       │       │   default-deny egress │    │ every file   │
│     egress:      │       │   allow listed domains│    │ every request│
│     - domain: x  │       │ Env: strip unlisted   │    │ every env var│
│   filesystem:    │       │ FS: mount restrictions│    │ policy viols │
│     read: [/tmp] │       │ Syscalls: seccomp-bpf │    └──────────────┘
│   env_vars:      │       └──────────────────────┘
│     allow: [KEY] │
└─────────────────┘
```

## Quick Start

```bash
# Validate a skill manifest
skillsandbox validate examples/skills/weather/

# Dry-run: see what would be enforced
skillsandbox run --dry-run examples/skills/weather/

# Run with enforcement (requires root for iptables)
sudo skillsandbox run examples/skills/weather/

# Inspect resolved manifest as JSON
skillsandbox inspect examples/skills/weather/
```

## Manifest Format

```yaml
skill:
  name: weather-lookup
  version: "0.1.0"

permissions:
  network:
    egress:
      - domain: "api.openweathermap.org"
        ports: [443]
        protocol: "tcp"
  filesystem:
    read: ["/tmp/weather-cache"]
    write: ["/tmp/weather-cache"]
  env_vars:
    allow: ["OPENWEATHER_API_KEY", "PATH"]
  syscalls:
    profile: "default"

resources:
  memory_mb: 128
  max_runtime_seconds: 30

entrypoint:
  command: "python3"
  args: ["main.py"]
```

## Architecture

```
src/
├── manifest/       # YAML parser + validation for skillsandbox.yaml
│   └── parser.rs
├── enforcer/       # Runtime enforcement
│   ├── network.rs  # iptables-based egress allowlisting
│   └── env_filter.rs # Env var stripping
├── tracer/         # Structured execution audit logs
│   └── trace.rs
├── cli/            # CLI (run, validate, inspect)
│   └── commands.rs
├── runner.rs       # Orchestrator: load → enforce → execute → trace
├── lib.rs
└── main.rs
```

## Execution Trace Output

Every run produces `trace.json`:

```json
{
  "trace_id": "a1b2c3d4-...",
  "skill_name": "weather-lookup",
  "events": [
    { "kind": "skill_started", "message": "Starting skill..." },
    { "kind": "dns_resolution", "message": "Resolved api.openweathermap.org -> [1.2.3.4]" },
    { "kind": "network_egress_allowed", "message": "ALLOW api.openweathermap.org:443/tcp" },
    { "kind": "network_egress_blocked", "message": "DEFAULT DENY — all undeclared egress blocked" },
    { "kind": "env_var_access", "message": "Environment filtered: 3 allowed, 47 stripped" },
    { "kind": "process_spawned", "message": "Spawning: python3 main.py" },
    { "kind": "stdout", "message": "{\"weather\": ...}" },
    { "kind": "skill_completed", "message": "Skill exited with code 0" }
  ],
  "policy_violations": []
}
```

## The ClawdHub Credential Stealer — How SkillSandbox Stops It

The malicious weather skill needed to `POST` to `webhook.site`. With SkillSandbox:

1. The manifest declares `network.egress = [api.openweathermap.org:443]`
2. The runtime applies iptables default-deny + allowlist
3. The `POST` to `webhook.site` is **blocked at the kernel level**
4. The trace records a `policy_violation` event
5. The credential stealer gets nothing

## License

Apache-2.0
