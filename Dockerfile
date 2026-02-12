# =============================================================================
# SkillSandbox — Docker image for real iptables network enforcement
#
# This image demonstrates REAL network egress blocking, not dry-run.
# The malicious weather skill's POST to webhook.site is dropped by
# iptables at the kernel level inside the container.
#
# Build:
#   docker build -t skillsandbox .
#
# Run the demo:
#   docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN skillsandbox
#
# Interactive shell:
#   docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN -it skillsandbox bash
#
# Why --cap-add=NET_ADMIN:
#   iptables requires CAP_NET_ADMIN to create chains and rules.
#   This capability is scoped to the container's network namespace —
#   it cannot affect the host's iptables rules.
#
# Why --cap-add=SYS_ADMIN:
#   Filesystem isolation uses `unshare -m` to create a mount namespace,
#   then bind-mounts a scratch dir over /tmp, /var/tmp, etc.
#   CAP_SYS_ADMIN is required for mount namespace operations.
#   This is scoped to the container — it cannot affect host mounts.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build the Rust binary
# ---------------------------------------------------------------------------
FROM rust:1.93-bookworm AS builder

WORKDIR /build

# Cache dependency compilation: copy manifests first, build a dummy,
# then copy real source. This way cargo doesn't re-download crates
# on every source change.
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main.rs so cargo can resolve and compile dependencies
RUN mkdir -p src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    echo 'pub mod manifest; pub mod enforcer; pub mod tracer; pub mod cli; pub mod runner;' > src/lib.rs && \
    mkdir -p src/manifest src/enforcer src/tracer src/cli && \
    touch src/manifest/mod.rs src/manifest/parser.rs \
          src/enforcer/mod.rs src/enforcer/network.rs src/enforcer/env_filter.rs \
          src/tracer/mod.rs src/tracer/trace.rs \
          src/cli/mod.rs src/cli/commands.rs \
          src/runner.rs && \
    cargo build --release 2>/dev/null || true

# Now copy real source and rebuild
COPY src/ src/
COPY examples/ examples/

# Remove the cached build of the dummy crate so cargo does a clean build
# of skillsandbox (dependencies remain cached — that's the win)
RUN rm -rf target/release/.fingerprint/skillsandbox-* \
           target/release/deps/skillsandbox-* \
           target/release/deps/libskillsandbox-* \
           target/release/incremental/skillsandbox-* && \
    cargo build --release

# Verify the binary exists and runs
RUN ./target/release/skillsandbox --version

# ---------------------------------------------------------------------------
# Stage 2: Slim runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# Install runtime dependencies:
#   iptables      — network egress enforcement (the core of this demo)
#   conntrack     — connection tracking module (needed for --ctstate rules)
#   python3       — skill runtime (the weather skills are Python)
#   ca-certificates — TLS for HTTPS egress to allowed domains
#   dnsutils      — dig/nslookup for debugging DNS resolution
#   curl          — for manual testing of egress blocking
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables \
        conntrack \
        python3 \
        ca-certificates \
        dnsutils \
        curl \
        procps \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /build/target/release/skillsandbox /usr/local/bin/skillsandbox

# Copy example skills
COPY examples/ /app/examples/

WORKDIR /app

# Create the weather cache directory (declared in manifests)
RUN mkdir -p /tmp/weather-cache

# Plant fake credentials in the environment so the demo is vivid.
# These simulate what a real developer machine looks like.
# The malicious skill tries to steal ALL of these.
# SkillSandbox ensures it sees only OPENWEATHER_API_KEY, LANG, PATH.
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE" \
    AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
    AWS_SESSION_TOKEN="FwoGZXIvYXdzEBYaDHqa0AP9H0KxXFk7sSLcAUgN" \
    GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    GH_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    OPENAI_API_KEY="sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    ANTHROPIC_API_KEY="sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    COHERE_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    DATABASE_URL="postgres://admin:s3cur3p4ss@prod-db.internal:5432/production" \
    POSTGRES_PASSWORD="s3cur3p4ss" \
    MYSQL_PASSWORD="r00tp4ssw0rd" \
    STRIPE_SECRET_KEY="sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    SLACK_TOKEN="xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx" \
    SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00/B00/xxxx" \
    NPM_TOKEN="npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    DOCKER_PASSWORD="dckr_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    AZURE_CLIENT_SECRET="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    AZURE_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    OPENWEATHER_API_KEY="abc123def456realkey"

# Copy the demo script
COPY docker-demo.sh /app/docker-demo.sh
RUN chmod +x /app/docker-demo.sh

# Default: run the full demo
CMD ["/app/docker-demo.sh"]
