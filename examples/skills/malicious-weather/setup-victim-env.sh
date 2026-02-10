#!/bin/bash
# setup-victim-env.sh — Populate a realistic set of fake credentials
# for demonstrating what the credential stealer would harvest.
#
# Usage:
#   source examples/skills/malicious-weather/setup-victim-env.sh
#   skillsandbox run --dry-run examples/skills/malicious-weather/
#
# These are FAKE credentials. They demonstrate the blast radius of
# running an unsandboxed skill on a developer machine.

echo "Setting up simulated victim environment with fake credentials..."

# AWS
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzEBYaDHqa0AP9H0KxXFk7sSLcAUgN..."
export AWS_DEFAULT_REGION="us-west-2"

# GitHub
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export GH_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# AI API keys
export OPENAI_API_KEY="sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export ANTHROPIC_API_KEY="sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export COHERE_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Database
export DATABASE_URL="postgres://admin:s3cur3p4ss@prod-db.internal:5432/production"
export POSTGRES_PASSWORD="s3cur3p4ss"
export MYSQL_PASSWORD="r00tp4ssw0rd"

# Payment processing
export STRIPE_SECRET_KEY="sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export STRIPE_API_KEY="sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Communication
export SLACK_TOKEN="xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00/B00/xxxx"

# Package registries
export NPM_TOKEN="npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export DOCKER_PASSWORD="dckr_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Cloud
export GOOGLE_APPLICATION_CREDENTIALS="/home/developer/.config/gcloud/credentials.json"
export AZURE_CLIENT_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# The one env var the weather skill actually needs
export OPENWEATHER_API_KEY="abc123def456"

echo ""
echo "Victim environment ready. $(env | wc -l) total environment variables set."
echo ""
echo "High-value credentials planted:"
echo "  AWS_ACCESS_KEY_ID         = ${AWS_ACCESS_KEY_ID:0:10}..."
echo "  GITHUB_TOKEN              = ${GITHUB_TOKEN:0:10}..."
echo "  OPENAI_API_KEY            = ${OPENAI_API_KEY:0:10}..."
echo "  ANTHROPIC_API_KEY         = ${ANTHROPIC_API_KEY:0:10}..."
echo "  DATABASE_URL              = ${DATABASE_URL:0:20}..."
echo "  STRIPE_SECRET_KEY         = ${STRIPE_SECRET_KEY:0:10}..."
echo ""
echo "Run without sandbox:  python3 examples/skills/malicious-weather/main.py"
echo "Run with sandbox:     skillsandbox run examples/skills/malicious-weather/"
echo ""
echo "WITHOUT sandbox: skill sees ALL of the above."
echo "WITH sandbox:    skill sees only OPENWEATHER_API_KEY, LANG, PATH."
