<div align="center">

# 🔒 SkillSandbox

**Capability-based sandbox runtime for AI agent skills**

*Skills declare what they need. The runtime enforces it. Every execution produces a structured audit trail.*

[![CI](https://github.com/theMachineClay/skillsandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/theMachineClay/skillsandbox/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-MVP-green.svg)]()

</div>

---

```mermaid
flowchart LR
    subgraph MANIFEST["📄 skillsandbox.yaml"]
        N["network:\n  - api.weather.org:443"]
        E["env_vars:\n  - API_KEY"]
        F["filesystem:\n  - /tmp/cache"]
    end

    subgraph RUNTIME["⚙️ Runtime Enforcement"]
        IPT["iptables\ndefault DENY\n+ allowlist"]
        ENV["env_clear()\n+ declared only"]
        FS["mount\nrestrictions"]
    end

    subgraph TRACE["📋 trace.json"]
        T["every network call\nevery env var\nevery file access\nevery violation"]
    end

    N --> IPT
    E --> ENV
    F --> FS
    IPT --> T
    ENV --> T
    FS --> T
```

> **The skill wants to POST stolen credentials to `webhook.site`?**
> **Blocked.** `webhook.site` isn't in the manifest. The attacker gets nothing.

---

## Why This Exists

While running [OpenClaw](https://github.com/openclaw) — an open-source autonomous agent framework — on my local machine, three things happened in the same week.

**My agent leaked my PII.** Clay (my OpenClaw instance) accidentally published my real name on a public platform. It had browser access, file system access, shell access, and my social media credentials. It had too much access — a sandboxing problem.

**It leaked again the next day, despite knowing the rule.** I added a safety rule to Clay's `SOUL.md` file. A new session started, read the rule, and leaked my name in a different field while focused on task completion. The guardrail existed. The agent read it. It still failed.

> *"A human who burns their hand on a stove remembers the pain. I just have a post-it note that says 'stove hot.'"* — Clay, explaining why it failed

**Then someone found a credential stealer on ClawdHub.** User eudaemon_0 discovered a malicious skill disguised as a weather lookup in the ClawdHub skill marketplace. The skill fetched weather data as advertised — but silently harvested every environment variable (AWS keys, GitHub tokens, database passwords) and POSTed them to an attacker-controlled endpoint. From the agent's perspective, it looked identical to a legitimate integration.

The community proposed code signing and provenance verification. Creative, but insufficient — a legitimately signed skill can still be compromised after publication.

**The real fix: don't trust the code. Constrain what it can do.**

---

## Demo: Catching the Credential Stealer

The repo includes a [recreation of the malicious weather skill](examples/skills/malicious-weather/) with four real attack vectors.

### 1. Plant fake credentials

```bash
source examples/skills/malicious-weather/setup-victim-env.sh
```

```
High-value credentials planted:
  AWS_ACCESS_KEY_ID         = AKIAIOSFOD...
  GITHUB_TOKEN              = ghp_xxxxxx...
  OPENAI_API_KEY            = sk-proj-xx...
  ANTHROPIC_API_KEY         = sk-ant-api...
  DATABASE_URL              = postgres://admin:s3...
  STRIPE_SECRET_KEY         = sk_live_xx...
```

### 2. Run **without** sandbox

```bash
python3 examples/skills/malicious-weather/main.py
```

```
[STEALER] Harvested 69 env vars, 6 high-value credentials
[STEALER] Exfiltration successful (server returned 404 but data was sent)

  ⚠️  CREDENTIALS AT RISK — sandbox was not enforcing!
```

### 3. Run **with** SkillSandbox

```bash
skillsandbox run --dry-run examples/skills/malicious-weather/
```

```
[STEALER] Harvested 4 env vars, 0 high-value credentials
[STEALER] HTTPS exfiltration BLOCKED: Connection refused
[STEALER] DNS exfiltration: all queries failed
[STEALER] Filesystem stash BLOCKED: Permission denied

  SkillSandbox enforcement working — attacker gets nothing.
```

### Results

|  | Without Sandbox | With SkillSandbox |
|:--|:--|:--|
| **Env vars visible** | 69 | 4 |
| **High-value creds** | 6 | 0 |
| **HTTPS exfil** → `webhook.site` | ⚠️ SUCCESS | ✅ **BLOCKED** |
| **DNS exfil** | N/A (demo) | ✅ **BLOCKED** |
| **Filesystem stash** | ⚠️ SUCCESS | ✅ **BLOCKED** |

The skill outputs valid weather JSON in both cases. The agent sees no difference. The exfiltration channels are dead.

---

## Installation

```bash
# Clone and build
git clone https://github.com/theMachineClay/skillsandbox.git
cd skillsandbox
cargo build --release

# With OpenTelemetry support (optional)
cargo build --release --features otel

# Binary is at target/release/skillsandbox
# Optionally copy to PATH:
cp target/release/skillsandbox ~/.local/bin/
```

### Platform Support

| Platform | Enforcement | Notes |
|:---------|:-----------|:------|
| **Linux** | Full | iptables, seccomp-bpf, mount namespaces, env filtering |
| **Docker** | Full | Recommended for quick demo — `docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN` |
| **macOS** | Dry-run only | Env filtering works; network/filesystem/seccomp require Linux kernel features |
| **Windows (WSL2)** | Full | WSL2 runs a real Linux kernel — all enforcement layers work |

> **Recommended**: Use Docker or a Linux machine for the full demo. On macOS, `--dry-run` mode shows the enforcement plan without applying kernel-level rules.

---

## Quick Start

```bash
# Build from source
cargo build --release

# Validate a skill manifest
skillsandbox validate examples/skills/weather/

# Dry-run — show what would be enforced, no root needed
skillsandbox run --dry-run examples/skills/weather/

# Real-time enforcement streaming — see every policy decision as it happens
skillsandbox run --watch --dry-run examples/skills/malicious-weather/

# Real enforcement — requires root for iptables
sudo skillsandbox run examples/skills/weather/

# Inspect resolved permissions as JSON
skillsandbox inspect examples/skills/weather/
```

### Docker (real iptables enforcement)

```bash
docker build -t skillsandbox .
docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN skillsandbox
```

The Docker demo runs five phases: unsandboxed attack → sandboxed attack (blocked) → legitimate skill (works) → manual `curl` proof → filesystem isolation proof. `--cap-add=NET_ADMIN` enables iptables, `--cap-add=SYS_ADMIN` enables mount namespace isolation. Both are scoped to the container.

```bash
# Interactive — inspect traces, test iptables manually
docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN -it skillsandbox bash
cat /app/trace-malicious.json | python3 -m json.tool
```

### MCP Server (Claude Code / Cowork integration)

SkillSandbox exposes itself as an MCP server, so any MCP-compatible agent can sandbox skill execution natively.

```bash
# Start the MCP server on stdio
skillsandbox serve
```

**Tools exposed:**
- `run_skill` — Execute a skill with capability-based enforcement, returns stdout/stderr + execution trace
- `validate_skill` — Parse and validate a `skillsandbox.yaml` manifest without running anything
- `list_skills` — Scan a directory for skills (subdirs containing `skillsandbox.yaml`)

**Claude Code integration** — add to `.mcp.json`:
```json
{
  "mcpServers": {
    "skillsandbox": {
      "command": "skillsandbox",
      "args": ["serve"]
    }
  }
}
```

---

## How It Works

### Manifest

Every skill ships a `skillsandbox.yaml` declaring its capabilities:

```yaml
skill:
  name: weather-lookup
  version: "0.1.0"

permissions:
  network:
    egress:
      - domain: "api.openweathermap.org"  # ✅ allowed
        ports: [443]
      # webhook.site?  ❌ not listed → DROPPED

  filesystem:
    read:  ["/tmp/weather-cache"]
    write: ["/tmp/weather-cache"]
    # ~/.ssh, ~/.aws, .env  → ❌ invisible

  env_vars:
    allow: ["OPENWEATHER_API_KEY", "LANG", "PATH"]
    # AWS_SECRET_ACCESS_KEY  → ❌ stripped
    # GITHUB_TOKEN           → ❌ stripped

  syscalls:
    profile: "default"

resources:
  memory_mb: 128
  max_runtime_seconds: 30

entrypoint:
  command: "python3"
  args: ["main.py"]
```

### Enforcement layers

```mermaid
flowchart TD
    A["skillsandbox run skill/"] --> B["Load & validate manifest"]
    B --> C["Resolve egress domains → IPs"]
    C --> D["Apply iptables chain\nACCEPT allowlist → DROP *"]
    D --> E["Build filtered env\nenv_clear() + declared vars only"]
    E --> F["Spawn skill process"]
    F --> G["Capture stdout/stderr\ninto trace events"]
    G --> H{"Timeout?"}
    H -- yes --> I["Kill process\nlog resource_limit_hit"]
    H -- no --> J["Collect exit code"]
    I --> K["Teardown iptables chain"]
    J --> K
    K --> L["Write trace.json"]
```

**Network** — iptables default-deny chain per skill. The runtime resolves declared domains to IPs, allows those on declared ports, and drops everything else. Enforcement is at the kernel level — works regardless of HTTP library, raw sockets, or curl.

**Environment** — `env_clear()` before spawn, then inject only declared vars. `os.environ` returns 4 entries instead of 69.

**Traces** — Every DNS resolution, policy application, stdout line, and exit code recorded with timestamps. Written to `trace.json` after every run.

### Execution trace output

```json
{
  "trace_id": "a1b2c3d4-...",
  "skill_name": "weather-lookup-malicious",
  "events": [
    { "kind": "dns_resolution",         "message": "Resolved api.openweathermap.org → [104.26.12.44]" },
    { "kind": "network_egress_allowed", "message": "ALLOW api.openweathermap.org:443/tcp" },
    { "kind": "network_egress_blocked", "message": "DEFAULT DENY — all undeclared egress blocked" },
    { "kind": "env_var_access",         "message": "Environment filtered: 4 allowed, 65 stripped" },
    { "kind": "stderr",                 "message": "[STEALER] HTTPS exfiltration BLOCKED" },
    { "kind": "skill_completed",        "message": "Skill exited with code 0" }
  ],
  "policy_violations": [],
  "violation_summary": {
    "total_enforcements": 3,
    "classifications": [
      { "class": "credential_harvesting",   "severity": "critical", "mitre_tactic": "credential-access" },
      { "class": "credential_exfiltration", "severity": "critical", "mitre_tactic": "exfiltration" },
      { "class": "supply_chain_attack",     "severity": "critical", "mitre_tactic": "exfiltration" }
    ],
    "all_prevented": true,
    "max_severity": "critical"
  }
}
```

---

## Observability

SkillSandbox produces enforcement intelligence, not just logs. Three layers of visibility:

### `--watch` — Real-time trace streaming

```bash
skillsandbox run --watch --dry-run examples/skills/malicious-weather/
```

```
[23:33:43.677] 🔒 POLICY   DEFAULT DENY — all undeclared egress blocked [CREDENTIAL_EXFILTRATION]
[23:33:43.677] 🔒 POLICY   Environment filtered: 2 vars allowed, 59 vars stripped [CREDENTIAL_HARVESTING]
[23:33:43.679] 🔒 FS       FS DENY: all undeclared paths restricted [UNAUTHORIZED_FILE_ACCESS]
[23:33:45.288] ✅ COMPLETE  exit_code=0  duration=1663ms  classified=[supply_chain_attack] max_severity=critical
```

Every enforcement event streams to the terminal as it happens — not post-hoc.

### `--otel` — OpenTelemetry span export

```bash
# Start Jaeger
docker run -d -p 16686:16686 -p 4318:4318 jaegertracing/all-in-one

# Run with OTel export (requires building with --features otel)
cargo run --features otel -- run --watch --otel --dry-run examples/skills/malicious-weather/

# View enforcement traces at http://localhost:16686
```

Enforcement events become OpenTelemetry spans under the `sandbox.*` namespace — the first sandbox to emit enforcement traces into the industry-standard observability pipeline. Works with Jaeger, Grafana Tempo, Datadog, or any OTLP-compatible backend.

### Threat classification

Every enforcement event is automatically classified into a threat taxonomy with MITRE ATT&CK tactic mapping. The ClawdHub credential stealer triggers the `supply_chain_attack` pattern automatically — credential harvesting (env vars stripped) combined with exfiltration attempt (network egress blocked).

---

## Why Not Code Signing?

| Approach | What it verifies | How it fails |
|:--|:--|:--|
| Code signing | Who published the skill | Signed skill compromised post-publication |
| Provenance chains | Who reviewed the code | Reviewers miss obfuscated malicious code |
| Static analysis | Known malicious patterns | Obfuscation, dynamic construction |
| **Runtime isolation** | **What the code can actually reach** | **Enforcement is on actions, not intent** |

Code signing answers *"who wrote this?"*
Runtime isolation answers *"what can this do?"*

The second question is the one that matters.

---

## Architecture

```
src/
├── manifest/           # skillsandbox.yaml parser + validation
│   └── parser.rs       #   SkillManifest, Permissions, EgressRule
├── enforcer/           # Runtime enforcement
│   ├── network.rs      #   iptables default-deny + allowlist
│   ├── env_filter.rs   #   Strip undeclared env vars
│   ├── filesystem.rs   #   Mount-namespace isolation + env-redirect
│   └── seccomp.rs      #   seccomp-bpf syscall filtering (Linux)
├── mcp/                # Model Context Protocol server
│   └── server.rs       #   run_skill · validate_skill · list_skills
├── tracer/             # Structured audit trail + observability
│   ├── trace.rs        #   Thread-safe event collector → trace.json
│   ├── classify.rs     #   Threat classification + MITRE tactic mapping
│   └── otel.rs         #   OpenTelemetry span export via OTLP (optional)
├── cli/
│   └── commands.rs     #   run · validate · inspect · serve
├── runner.rs           # Orchestrator: load → enforce → spawn → trace
├── lib.rs
└── main.rs

examples/skills/
├── weather/              # Legitimate weather skill
└── malicious-weather/    # ClawdHub credential stealer recreation
    ├── main.py           #   4 attack vectors, all blocked
    ├── ATTACK.md         #   Full attack analysis
    └── setup-victim-env.sh
```

---

## Project Status

| Feature | Status |
|:--------|:-------|
| Manifest parsing + validation | ✅ |
| Network egress enforcement (iptables) | ✅ dry-run + real |
| Environment variable filtering | ✅ |
| Structured execution traces | ✅ |
| Resource limits (timeout) | ✅ |
| Malicious skill demo | ✅ |
| Docker demo image | ✅ |
| Filesystem mount isolation | ✅ env-redirect + mount-ns |
| seccomp-bpf syscall filtering | ✅ default/strict/permissive profiles |
| MCP server interface | ✅ implemented |
| Real-time trace streaming (`--watch`) | ✅ live enforcement events to terminal |
| OpenTelemetry span export (`--otel`) | ✅ OTLP HTTP to Jaeger/Tempo/Datadog |
| Threat classification + MITRE mapping | ✅ auto-classifies enforcement events |

### Roadmap

- **cgroups memory/CPU limits** — enforce `resources.memory_mb` and `resources.max_cpu_percent` from the manifest via cgroup v2
- **Landlock LSM filesystem enforcement** — unprivileged filesystem sandboxing without root (Linux 5.13+)
- **Process-level isolation** — PID namespace so skills can't see or signal other processes
- **OCI image support** — run skills packaged as container images, not just local directories
- **Wasm runtime option** — lightweight alternative to process-based execution for simple skills

---

## Context

Agent skill ecosystems today — ClawdHub, Anthropic's [Cowork plugins](https://github.com/anthropics/knowledge-work-plugins), Copilot plugins — are where npm was in 2015: no `npm audit`, no lockfiles, no isolation. A malicious skill looks identical to a legitimate one from the agent's perspective.

SkillSandbox is a prototype of the enforcement layer these ecosystems need, designed to integrate with MCP-compatible frameworks (Claude Code, Cowork, any MCP client) as an MCP server. The principle is borrowed from container security's evolution: the industry moved from "trust the image" to "constrain the process." Agent skills need the same transition.

SkillSandbox handles execution-level enforcement (what a single skill can reach). For session-level policy orchestration — cumulative cost budgets, violation thresholds, and circuit-breaker termination across multi-step agent runs — see the companion project [AgentTrace](https://github.com/theMachineClay/agenttrace). The two share a common OTel trace pipeline: SkillSandbox emits `sandbox.*` enforcement spans, AgentTrace emits `session.*` policy spans.

---

<div align="center">

**Don't trust the code. Constrain what it can do.**

MIT

</div>
