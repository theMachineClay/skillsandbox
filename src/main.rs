use anyhow::Result;
use clap::Parser;
use skillsandbox::cli::{Cli, Commands};
use skillsandbox::manifest::SkillManifest;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // For MCP serve mode, we need tracing on stderr only (stdout is for JSON-RPC)
    #[cfg(feature = "mcp")]
    let is_serve = matches!(cli.command, Commands::Serve);
    #[cfg(not(feature = "mcp"))]
    let is_serve = false;

    if is_serve {
        // MCP mode: log to stderr at warn level to avoid polluting JSON-RPC on stdout
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
            )
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_target(false)
            .init();
    }

    match cli.command {
        Commands::Run {
            skill_dir,
            dry_run,
            trace_output,
            args,
        } => {
            let exit_code = skillsandbox::runner::run_skill(
                &skill_dir,
                dry_run,
                &args,
                trace_output.as_deref(),
            )
            .await?;
            std::process::exit(exit_code);
        }

        Commands::Validate { path } => {
            let manifest_path = if path.is_dir() {
                path.join("skillsandbox.yaml")
            } else {
                path
            };
            match SkillManifest::from_file(&manifest_path) {
                Ok(m) => {
                    println!("✓ Valid manifest: {} v{}", m.skill.name, m.skill.version);
                    println!(
                        "  Network egress: {} rule(s)",
                        m.permissions.network.egress.len()
                    );
                    println!(
                        "  Filesystem read: {} path(s)",
                        m.permissions.filesystem.read.len()
                    );
                    println!(
                        "  Filesystem write: {} path(s)",
                        m.permissions.filesystem.write.len()
                    );
                    println!(
                        "  Env vars: {} allowed",
                        m.permissions.env_vars.allow.len()
                    );
                    println!(
                        "  Resources: {}MB RAM, {}s timeout",
                        m.resources.memory_mb, m.resources.max_runtime_seconds
                    );
                }
                Err(e) => {
                    eprintln!("✗ Invalid manifest: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Inspect { path } => {
            let manifest_path = if path.is_dir() {
                path.join("skillsandbox.yaml")
            } else {
                path
            };
            let manifest = SkillManifest::from_file(&manifest_path)?;
            let json = serde_json::to_string_pretty(&manifest)?;
            println!("{}", json);
        }

        #[cfg(feature = "mcp")]
        Commands::Serve => {
            use rmcp::{transport::stdio, ServiceExt};
            use skillsandbox::mcp::SkillSandboxMcp;

            eprintln!("SkillSandbox MCP server starting on stdio...");
            let service = SkillSandboxMcp::new();
            let server = service.serve(stdio()).await?;
            eprintln!("SkillSandbox MCP server ready — waiting for requests");
            server.waiting().await?;
            eprintln!("SkillSandbox MCP server shutting down");
        }
    }

    Ok(())
}
