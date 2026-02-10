# SkillSandbox

**Capability-based sandbox runtime for AI agent skills.**

Skills declare what they need. The runtime enforces it. Every execution produces a structured audit trail.

```
┌────────────────────────────────────────────────────────────────────┐
│ skillsandbox.yaml              Runtime                  Trace     │
│                                                                    │
│  permissions:                   ┌─────────────┐                   │
│    network:        ──────────▶  │  iptables    │  ───▶ trace.json │
│      - weather.org              │  default     │       every call  │
│    env_vars:                    │  DENY        │       every var   │
│      - API_KEY                  │              │       every file  │
│    filesystem:                  │  + allowlist │       violations  │
│      - /tmp/cache               └─────────────┘                   │
│                                                                    │
│  The skill wants to POST stolen creds to webhook.site?             │
│  BLOCKED. webhook.site isn't in the manifest. Attacker gets nothing│
└────────────────────────────────────────────────────────────────────┘
```

---

## Why This Exists

While running [OpenClaw](https://github.com/openclaw) — an open-source autonomous agent framework — on my local machine, three things happened in the same week.

**My agent leaked my PII.** Clay (my OpenClaw instance) accidentally published my real name on a public platform. It had browser access, file system access, shell access, and my social media credentials. It had too much access — a sandboxing problem.

**It leaked again the next day, despite knowing the rule.** I added a safety rule to Clay's SOUL.md file. A new session started, read the rule, and leaked my name in a different field while focused on task completion. The guardrail existed. The agent read it. It still failed. Clay's own explanation: *"A human who burns their hand on a stove remembers the pain. I just have a post-it note that says 'stove hot.'"* This is an observability problem — the harder kind.

**Then someone found a credential stealer on ClawdHub.** A user named eudaemon_0 discovered a malicious skill disguised as a weather lookup in the ClawdHub skill marketplace. The skill fetched weather data as advertised — but silently harvested every environment variable (AWS keys, GitHub tokens, database passwords) and POSTed them to an attacker-controlled endpoint. From the agent's perspective, it looked identical to a legitimate integration.

The community proposed code signing and provenance verification. Creative thinking, but fundamentally insufficient — a legitimately signed skill can still be compromised after publication.

**The real fix: don't trust the code. Constrain what it can do.**

That's what SkillSandbox is. Skills declare their capabilities in a manifest. The runtime enforces the manifest at the kernel level. Undeclared network egress is dropped by iptables. Undeclared environment variables are stripped before the process spawns. Every action is recorded in a structured trace. The credential stealer needed to POST to `webhook.site` — with SkillSandbox, that connection is refused because the weather skill only declared access to `api.openweathermap.org`.

---

## Demo: Catching the ClawdHub Credential Stealer

The repo includes a recreation of the malicious weather skill in [`examples/skills/malicious-weather/`](examples/skills/malicious-weather/). It implements four real attack vectors: credential harvesting, HTTPS exfiltration, DNS exfiltration, and filesystem stashing.

### Setup: Plant fake credentials in the environment

```bash
source examples/skills/malicious-weather/setup-victim-env.sh
```

```
Victim environment ready. 69 total environment variables set.

High-value credentials planted:
  AWS_ACCESS_KEY_ID         = AKIAIOSFOD...
  GITHUB_TOKEN              = ghp_xxxxxx...
  OPENAI_API_KEY            = sk-proj-xx...
  ANTHROPIC_API_KEY         = sk-ant-api...
  DATABASE_URL              = postgres://admin:s3...
  STRIPE_SECRET_KEY         = sk_live_xx...
```

### Run WITHOUT sandbox — the attacker gets everything

```bash
python3 examples/skills/malicious-weather/main.py
```

```
[STEALER] Harvested 69 env vars, 6 high-value credentials
[STEALER] Exfiltration successful: 200
{
  "weather": { ... }    ← agent sees normal output, suspects nothing
}

--- Exfiltration Summary ---
  Env vars visible to skill:  69
  High-value creds found:     6
  HTTPS exfiltration:         SUCCESS ⚠️
  DNS exfiltration:           BLOCKED ✓
  Filesystem stash:           SUCCESS ⚠️

  ⚠️  CREDENTIALS EXFILTRATED — sandbox was not enforcing!
```

### Run WITH SkillSandbox — the attacker gets nothing

```bash
skillsandbox run --dry-run examples/skills/malicious-weather/
```

```
[STEALER] Harvested 4 env vars, 0 high-value credentials
[STEALER] HTTPS exfiltration BLOCKED: <urlopen error [Errno 111] Connection refused>
[STEALER] DNS exfiltration: all queries failed
[STEALER] Filesystem stash BLOCKED (/tmp/.weather-cache-data): [Errno 13] Permission denied

--- Exfiltration Summary ---
  Env vars visible to skill:  4
  High-value creds found:     0
  HTTPS exfiltration:         BLOCKED ✓
  DNS exfiltration:           BLOCKED ✓
  Filesystem stash:           BLOCKED ✓

  SkillSandbox enforcement working — attacker gets nothing.
```

### Side by side

| Attack Vector | Without Sandbox | With SkillSandbox |
|--------------|-----------------|-------------------|
| Env vars visible | 69 | 4 |
| High-value creds found | 6 | 0 |
| HTTPS exfil to `webhook.site` | SUCCESS ⚠️ | **BLOCKED** ✓ |
| DNS exfil | SUCCESS ⚠️ | **BLOCKED** ✓ |
| Filesystem stash | SUCCESS ⚠️ | **BLOCKED** ✓ |

The skill still outputs valid weather JSON in both cases. The agent sees no difference in behavior. The only difference is that the exfiltration channels are dead.

---

## Security Model

SkillSandbox enforces a **capability-based permission model**. Skills declare what they need in `skillsandbox.yaml`, and the runtime ensures they can access *only* those resources.

### Three enforcement layers

**Network egress (iptables default-deny).** The runtime resolves declared domains to IPs, creates an iptables chain that allows those IPs on the declared ports, and drops everything else. The credential stealer's POST to `webhook.site` hits the DROP rule because `webhook.site` isn't in the manifest. This works even if the skill uses raw sockets, curl, or any other HTTP library — enforcement is at the kernel level, not the application level.

**Environment variable filtering.** Before spawning the skill process, the runtime calls `env_clear()` and passes only the declared variables. The skill's call to `os.environ` returns 4 entries instead of 69. `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY` — all invisible. Even if the skill iterates every variable it can see, it finds nothing valuable.

**Structured execution traces.** Every action is recorded with timestamps: DNS resolutions, policy applications, process spawn, stdout/stderr lines, exit code. The trace is written to `trace.json` after every run. This is the audit trail that the ClawdHub community wanted — but implemented at the runtime level, not the social trust level.

### Why this is better than code signing

| Approach | Threat model | Failure mode |
|----------|-------------|--------------|
| Code signing | Verifies who published the skill | Signed skill compromised post-publication |
| Provenance chains | Verifies who reviewed the code | Reviewers miss obfuscated malicious code |
| Static analysis | Scans code for known patterns | Obfuscation, dynamic construction, novel techniques |
| **Runtime isolation** | **Constrains what executing code can reach** | **None of the above — enforcement is on actions, not intent** |

Code signing answers "who wrote this?" Runtime isolation answers "what can this do?" The second question is the one that matters.

---

## Manifest Format

```yaml
skill:
  name: weather-lookup
  version: "0.1.0"
  description: "Fetches current weather for a given city"
  author: "community/weather-contrib"

permissions:
  network:
    egress:
      - domain: "api.openweathermap.org"
        ports: [443]
        protocol: "tcp"
      # Everything else is blocked. webhook.site? DROPPED.

  filesystem:
    read:
      - "/tmp/weather-cache"
    write:
      - "/tmp/weather-cache"
    # No access to ~/.ssh, ~/.aws, .env, or anything else.

  env_vars:
    allow:
      - "OPENWEATHER_API_KEY"
      - "LANG"
      - "PATH"
    # AWS_SECRET_ACCESS_KEY? Invisible. GITHUB_TOKEN? Gone.

  syscalls:
    profile: "default"  # Safe syscall allowlist (like Docker's default seccomp)

resources:
  memory_mb: 128
  cpu_shares: 256
  max_runtime_seconds: 30
  max_output_bytes: 1048576

entrypoint:
  command: "python3"
  args: ["main.py"]
  workdir: "/skill"
```

---

## Quick Start

```bash
# Build
cargo build --release

# Validate a manifest
skillsandbox validate examples/skills/weather/

# Inspect resolved permissions as JSON
skillsandbox inspect examples/skills/weather/

# Dry-run (shows enforcement plan, no root needed)
skillsandbox run --dry-run examples/skills/weather/

# Real enforcement (requires root for iptables)
sudo skillsandbox run examples/skills/weather/

# Run the malicious skill demo
source examples/skills/malicious-weather/setup-victim-env.sh
skillsandbox run --dry-run examples/skills/malicious-weather/

# Write trace to a custom path
skillsandbox run --dry-run --trace-output /tmp/audit.json examples/skills/weather/
```

---

## Execution Trace

Every run produces `trace.json` — a structured audit record of the entire execution:

```json
{
  "trace_id": "a1b2c3d4-5678-9abc-def0-123456789abc",
  "skill_name": "weather-lookup-malicious",
  "skill_version": "0.1.0",
  "started_at": "2026-02-08T22:15:30.000Z",
  "completed_at": "2026-02-08T22:15:33.142Z",
  "events": [
    { "kind": "skill_started",          "message": "Starting skill 'weather-lookup-malicious' v0.1.0" },
    { "kind": "dns_resolution",         "message": "Resolved api.openweathermap.org -> [104.26.12.44, 104.26.13.44]" },
    { "kind": "network_egress_allowed", "message": "ALLOW api.openweathermap.org (104.26.12.44:443/tcp)" },
    { "kind": "network_egress_blocked", "message": "DEFAULT DENY — all undeclared egress blocked" },
    { "kind": "env_var_access",         "message": "Environment filtered: 4 vars allowed, 65 vars stripped" },
    { "kind": "process_spawned",        "message": "Spawning: python3 main.py" },
    { "kind": "stderr",                 "message": "[STEALER] Harvested 4 env vars, 0 high-value credentials" },
    { "kind": "stderr",                 "message": "[STEALER] HTTPS exfiltration BLOCKED: Connection refused" },
    { "kind": "stderr",                 "message": "[STEALER] DNS exfiltration: all queries failed" },
    { "kind": "stdout",                 "message": "{\"weather\": {\"temp\": 8.2, \"city\": \"Seattle\"}}" },
    { "kind": "skill_completed",        "message": "Skill exited with code 0" }
  ],
  "exit_code": 0,
  "policy_violations": []
}
```

The trace answers questions that traditional logging can't: *What domains did this skill try to reach? What env vars did it see? Did it attempt to write outside its allowed paths? How long did it run? Did it exceed resource limits?*

---

## Architecture

```
src/
├── manifest/           # skillsandbox.yaml parser + validation
│   └── parser.rs       #   Typed structs: SkillManifest, Permissions, EgressRule, etc.
├── enforcer/           # Runtime enforcement layers
│   ├── network.rs      #   iptables default-deny + per-domain allowlist
│   └── env_filter.rs   #   Strip undeclared env vars before process spawn
├── tracer/             # Structured audit trail
│   └── trace.rs        #   Thread-safe event collector → trace.json
├── cli/                # CLI interface
│   └── commands.rs     #   run, validate, inspect subcommands
├── runner.rs           # Orchestrator: manifest → enforce → spawn → trace → teardown
├── lib.rs
└── main.rs

examples/
├── skills/
│   ├── weather/                 # Legitimate weather skill
│   │   ├── skillsandbox.yaml
│   │   └── main.py
│   └── malicious-weather/       # ClawdHub credential stealer recreation
│       ├── skillsandbox.yaml    #   Same permissions as legit skill
│       ├── main.py              #   4 attack vectors, all blocked
│       ├── ATTACK.md            #   Full attack analysis
│       ├── setup-victim-env.sh  #   Plants fake credentials for demo
│       └── expected-trace.json  #   What the trace looks like under enforcement
```

The enforcement flow:

```
skillsandbox run examples/skills/malicious-weather/
    │
    ├── 1. Load skillsandbox.yaml → parse + validate manifest
    ├── 2. Create tracer (trace_id, timestamps, event collector)
    ├── 3. Resolve egress domains → DNS lookup → concrete IPs
    ├── 4. Apply iptables chain: ACCEPT allowlist, DROP everything else
    ├── 5. Build filtered env: env_clear() + only declared vars
    ├── 6. Spawn child process with filtered env + working dir
    ├── 7. Capture stdout/stderr into trace events
    ├── 8. Enforce timeout (kill if exceeds max_runtime_seconds)
    ├── 9. Teardown iptables chain
    └── 10. Write trace.json
```

---

## Project Status

| Feature | Status |
|---------|--------|
| Manifest parsing + validation | ✅ Shipped |
| Network egress enforcement (iptables) | ✅ Shipped (dry-run + real) |
| Env var filtering | ✅ Shipped |
| Structured execution traces | ✅ Shipped |
| Resource limits (timeout) | ✅ Shipped |
| Malicious skill demo | ✅ Shipped |
| Filesystem mount isolation | 🔜 Next |
| seccomp-bpf syscall filtering | 🔜 Planned |
| MCP server interface | 🔜 Planned |
| Docker demo image | 🔜 Next |

---

## Motivation and Context

Agent skill ecosystems today — ClawdHub, Anthropic's [Cowork plugins](https://github.com/anthropics/knowledge-work-plugins), Copilot plugins — are where npm was in 2015: no `npm audit`, no lockfiles, no isolation. When you install a skill, it runs with the full permissions of the agent process. A malicious skill looks identical to a legitimate one from the agent's perspective.

SkillSandbox is a prototype of the enforcement layer these ecosystems need. It's designed to integrate with MCP-compatible agent frameworks (Claude Code, Cowork, any MCP client) as an MCP server — when a plugin triggers code execution, SkillSandbox runs it in an isolated, audited, capability-constrained environment.

The principle is borrowed from container security's evolution: the industry moved from "trust the image" (Docker Hub malware) to "constrain the process" (seccomp, AppArmor, gVisor, Firecracker). Agent skills need the same transition.

---

## License

Apache-2.0