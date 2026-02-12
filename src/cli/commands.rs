use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "skillsandbox",
    about = "Capability-based sandbox runtime for AI agent skills",
    long_about = "SkillSandbox enforces capability-based permissions for AI agent skills.\n\
        Skills declare what they need (network endpoints, filesystem paths, env vars).\n\
        The runtime enforces isolation — undeclared access is blocked.\n\
        Every execution produces a structured audit trail.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a skill inside the sandbox
    Run {
        /// Path to the skill directory (must contain skillsandbox.yaml)
        #[arg(value_name = "SKILL_DIR")]
        skill_dir: PathBuf,

        /// Dry-run: show what would be enforced without applying iptables rules
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Path to write the execution trace JSON
        #[arg(long, value_name = "FILE")]
        trace_output: Option<PathBuf>,

        /// Extra arguments passed to the skill entrypoint
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Validate a skillsandbox.yaml manifest
    Validate {
        /// Path to skillsandbox.yaml or skill directory
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Inspect a manifest: show resolved permissions and policy
    Inspect {
        /// Path to skillsandbox.yaml or skill directory
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Start the MCP (Model Context Protocol) server over stdio.
    /// This allows AI agents like Claude Code and Cowork to run skills
    /// inside the sandbox via tool calls.
    #[cfg(feature = "mcp")]
    Serve,
}
