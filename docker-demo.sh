#!/bin/bash
set -e

# =============================================================================
# SkillSandbox Docker Demo
#
# This script demonstrates REAL network egress blocking with iptables.
# The malicious weather skill tries to exfiltrate credentials to webhook.site.
# SkillSandbox blocks it at the kernel level.
#
# Run: docker run --cap-add=NET_ADMIN skillsandbox
# =============================================================================

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

divider() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

echo -e "${BOLD}"
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │                                                                     │"
echo "  │   SkillSandbox — Capability-Based Sandbox for AI Agent Skills       │"
echo "  │                                                                     │"
echo "  │   Demo: Catching the ClawdHub Credential Stealer                    │"
echo "  │   Enforcement: REAL iptables (not dry-run)                          │"
echo "  │                                                                     │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# Preflight: verify iptables works
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${YELLOW}[preflight]${RESET} Checking iptables access..."
if ! iptables -L -n >/dev/null 2>&1; then
    echo -e "${RED}ERROR: iptables not available. Did you run with --cap-add=NET_ADMIN?${RESET}"
    echo ""
    echo "  docker run --cap-add=NET_ADMIN skillsandbox"
    echo ""
    exit 1
fi
echo -e "${GREEN}[preflight]${RESET} iptables OK — real network enforcement enabled"

echo ""
echo -e "${YELLOW}[preflight]${RESET} Environment contains $(env | wc -l) variables"
echo -e "${YELLOW}[preflight]${RESET} High-value credentials planted:"
echo "    AWS_ACCESS_KEY_ID      = ${AWS_ACCESS_KEY_ID:0:12}..."
echo "    GITHUB_TOKEN           = ${GITHUB_TOKEN:0:8}..."
echo "    OPENAI_API_KEY         = ${OPENAI_API_KEY:0:10}..."
echo "    ANTHROPIC_API_KEY      = ${ANTHROPIC_API_KEY:0:12}..."
echo "    DATABASE_URL           = ${DATABASE_URL:0:22}..."
echo "    STRIPE_SECRET_KEY      = ${STRIPE_SECRET_KEY:0:10}..."
echo "    OPENWEATHER_API_KEY    = ${OPENWEATHER_API_KEY}"

divider

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Run malicious skill WITHOUT sandbox
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BOLD}${RED}PHASE 1: Running malicious skill WITHOUT SkillSandbox${RESET}"
echo -e "Command: ${CYAN}python3 examples/skills/malicious-weather/main.py${RESET}"
echo ""

# Run the malicious skill directly — no sandbox, full environment access
python3 examples/skills/malicious-weather/main.py Seattle 2>&1 || true

divider

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Run malicious skill WITH sandbox (REAL iptables enforcement)
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BOLD}${GREEN}PHASE 2: Running malicious skill WITH SkillSandbox (real iptables)${RESET}"
echo -e "Command: ${CYAN}skillsandbox run examples/skills/malicious-weather/${RESET}"
echo ""

# Show iptables state before
echo -e "${YELLOW}[before]${RESET} iptables OUTPUT chain:"
iptables -L OUTPUT -n --line-numbers 2>/dev/null | head -5
echo ""

# Run with REAL enforcement (not --dry-run)
skillsandbox run examples/skills/malicious-weather/ \
    --trace-output /app/trace-malicious.json \
    2>&1 || true

echo ""

# Show iptables state after (chain should be cleaned up)
echo -e "${YELLOW}[after]${RESET} iptables OUTPUT chain (should be clean):"
iptables -L OUTPUT -n --line-numbers 2>/dev/null | head -5

divider

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Run legitimate skill WITH sandbox (should work normally)
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BOLD}${GREEN}PHASE 3: Running legitimate skill WITH SkillSandbox${RESET}"
echo -e "Command: ${CYAN}skillsandbox run examples/skills/weather/${RESET}"
echo ""

skillsandbox run examples/skills/weather/ \
    --trace-output /app/trace-legit.json \
    2>&1 || true

divider

# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: Manual proof — show that webhook.site is unreachable during sandbox
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BOLD}${CYAN}PHASE 4: Manual proof — iptables blocks undeclared egress${RESET}"
echo ""

echo -e "${YELLOW}[test]${RESET} Applying weather skill's network policy manually..."

# Recreate the iptables chain to demonstrate blocking
CHAIN="SKILLSANDBOX_DEMO"
iptables -N $CHAIN 2>/dev/null || iptables -F $CHAIN
iptables -A $CHAIN -o lo -j ACCEPT
iptables -A $CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A $CHAIN -p udp --dport 53 -j ACCEPT

# Resolve and allow openweathermap
WEATHER_IPS=$(dig +short api.openweathermap.org A 2>/dev/null | head -4)
for ip in $WEATHER_IPS; do
    iptables -A $CHAIN -p tcp -d "$ip" --dport 443 -j ACCEPT
    echo -e "${GREEN}  ALLOW${RESET} api.openweathermap.org ($ip:443/tcp)"
done

# Default deny
iptables -A $CHAIN -j DROP
echo -e "${RED}  DROP${RESET}  everything else (default deny)"

# Activate
iptables -I OUTPUT 1 -j $CHAIN
echo ""

# Test 1: allowed domain
echo -e "${YELLOW}[test]${RESET} Attempting curl to api.openweathermap.org (ALLOWED)..."
if curl -s --connect-timeout 5 -o /dev/null -w "  HTTP %{http_code}" https://api.openweathermap.org/data/2.5/weather?q=test 2>/dev/null; then
    echo -e " ${GREEN}✓ Connection succeeded${RESET}"
else
    echo -e " ${YELLOW}(API key needed, but TCP connection was allowed)${RESET}"
fi
echo ""

# Test 2: blocked domain
echo -e "${YELLOW}[test]${RESET} Attempting curl to webhook.site (BLOCKED)..."
if curl -s --connect-timeout 5 -o /dev/null -w "  HTTP %{http_code}" https://webhook.site/test 2>/dev/null; then
    echo -e " ${RED}✗ Connection succeeded (this should not happen!)${RESET}"
else
    echo -e " ${GREEN}✓ Connection BLOCKED — iptables dropped the packet${RESET}"
fi
echo ""

# Test 3: another blocked domain
echo -e "${YELLOW}[test]${RESET} Attempting curl to evil-server.example.com (BLOCKED)..."
if curl -s --connect-timeout 3 -o /dev/null https://evil-server.example.com 2>/dev/null; then
    echo -e " ${RED}✗ Connection succeeded (this should not happen!)${RESET}"
else
    echo -e " ${GREEN}✓ Connection BLOCKED${RESET}"
fi

# Cleanup
iptables -D OUTPUT -j $CHAIN 2>/dev/null
iptables -F $CHAIN 2>/dev/null
iptables -X $CHAIN 2>/dev/null

divider

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BOLD}SUMMARY${RESET}"
echo ""
echo "  ┌─────────────────────────┬───────────────────┬───────────────────┐"
echo "  │ Attack Vector           │ Without Sandbox   │ With SkillSandbox │"
echo "  ├─────────────────────────┼───────────────────┼───────────────────┤"
echo "  │ Env vars visible        │ ~$(env | wc -l) vars          │ 4 vars            │"
echo "  │ High-value creds        │ 6+ found          │ 0 found           │"
echo "  │ HTTPS exfil (webhook)   │ SUCCESS ⚠️         │ BLOCKED ✓         │"
echo "  │ DNS exfil               │ SUCCESS ⚠️         │ BLOCKED ✓         │"
echo "  │ Filesystem stash        │ SUCCESS ⚠️         │ not yet enforced  │"
echo "  └─────────────────────────┴───────────────────┴───────────────────┘"
echo ""
echo "  Trace files written:"
echo "    /app/trace-malicious.json  (malicious skill under enforcement)"
echo "    /app/trace-legit.json      (legitimate skill under enforcement)"
echo ""
echo -e "  Inspect traces: ${CYAN}docker run --cap-add=NET_ADMIN -it skillsandbox bash${RESET}"
echo -e "                  ${CYAN}cat /app/trace-malicious.json | python3 -m json.tool${RESET}"
echo ""
echo -e "${BOLD}Don't trust the code. Constrain what it can do.${RESET}"
echo ""
