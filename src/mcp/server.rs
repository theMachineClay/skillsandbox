//! SkillSandbox MCP Server
//!
//! Exposes SkillSandbox as a Model Context Protocol server, allowing
//! AI agents (Claude Code, Cowork, any MCP client) to run skills
//! inside capability-based sandboxes.
//!
//! Tools:
//!   - run_skill: Execute a skill directory with full sandbox enforcement
//!   - validate_skill: Validate a skillsandbox.yaml manifest
//!   - list_skills: List available skills in a directory

use crate::manifest::SkillManifest;
use crate::runner;
use rmcp::{
    model::*,
    service::RequestContext,
    service::RoleServer,
    ErrorData as McpError, ServerHandler,
};
use serde::Deserialize;
use std::borrow::Cow;
use std::future::Future;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Request types (deserialized from JSON arguments)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RunSkillRequest {
    pub skill_dir: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ValidateSkillRequest {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct ListSkillsRequest {
    pub directory: String,
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SkillSandboxMcp;

impl SkillSandboxMcp {
    pub fn new() -> Self {
        Self
    }

    fn make_tool(name: &str, description: &str, schema: serde_json::Value) -> Tool {
        let obj = match schema {
            serde_json::Value::Object(m) => m,
            _ => panic!("Tool schema must be a JSON object"),
        };
        Tool::new(name.to_string(), description.to_string(), obj)
    }

    fn tool_definitions() -> Vec<Tool> {
        vec![
            Self::make_tool(
                "run_skill",
                "Run an AI agent skill inside the SkillSandbox with capability-based enforcement. \
                 The skill must have a skillsandbox.yaml manifest declaring its required permissions \
                 (network endpoints, env vars, filesystem paths). All undeclared access is blocked. \
                 Returns stdout, stderr, and a structured execution trace.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "skill_dir": {
                            "type": "string",
                            "description": "Path to the skill directory containing skillsandbox.yaml"
                        },
                        "dry_run": {
                            "type": "boolean",
                            "description": "Dry-run mode: log enforcement plan without applying rules",
                            "default": false
                        },
                        "args": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Additional arguments passed to the skill process",
                            "default": []
                        }
                    },
                    "required": ["skill_dir"]
                }),
            ),
            Self::make_tool(
                "validate_skill",
                "Validate a skillsandbox.yaml manifest. Returns parsed permissions \
                 (network egress rules, filesystem paths, env vars), resource limits, \
                 and entrypoint configuration without executing the skill.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to skillsandbox.yaml file or skill directory"
                        }
                    },
                    "required": ["path"]
                }),
            ),
            Self::make_tool(
                "list_skills",
                "Scan a directory for AI agent skills (subdirectories containing skillsandbox.yaml). \
                 Returns the name, version, and declared permissions of each skill found.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "directory": {
                            "type": "string",
                            "description": "Directory to scan for skills (each subdirectory with skillsandbox.yaml)"
                        }
                    },
                    "required": ["directory"]
                }),
            ),
        ]
    }

    // ── Tool implementations ────────────────────────────────────────────

    async fn handle_run_skill(&self, req: RunSkillRequest) -> String {
        let skill_dir = PathBuf::from(&req.skill_dir);

        if !skill_dir.exists() {
            return format!("Error: Skill directory does not exist: {}", req.skill_dir);
        }

        let manifest_path = skill_dir.join("skillsandbox.yaml");
        if !manifest_path.exists() {
            return format!("Error: No skillsandbox.yaml found in: {}", req.skill_dir);
        }

        match runner::run_skill_inner(&skill_dir, req.dry_run, &req.args, None).await {
            Ok(result) => format!(
                "{summary}\n\n\
                 --- stdout ---\n{stdout}\n\n\
                 --- stderr ---\n{stderr}\n\n\
                 --- enforcement ---\n\
                 Exit code: {exit_code}\n\
                 Events: {events}\n\
                 Policy violations: {violations}",
                summary = result.summary,
                stdout = if result.stdout.is_empty() {
                    "(empty)".to_string()
                } else {
                    result.stdout.trim_end().to_string()
                },
                stderr = if result.stderr.is_empty() {
                    "(empty)".to_string()
                } else {
                    result.stderr.trim_end().to_string()
                },
                exit_code = result.exit_code,
                events = result.events,
                violations = result.violations,
            ),
            Err(e) => format!("Error: Skill execution failed: {:#}", e),
        }
    }

    fn handle_validate_skill(&self, req: ValidateSkillRequest) -> String {
        let path = PathBuf::from(&req.path);
        let manifest_path = if path.is_dir() {
            path.join("skillsandbox.yaml")
        } else {
            path
        };

        match SkillManifest::from_file(&manifest_path) {
            Ok(m) => format!(
                "✓ Valid manifest: {} v{}\n\
                 \n\
                 Entrypoint: {} {}\n\
                 \n\
                 Permissions:\n\
                   Network egress: {} rule(s)\n\
                   Filesystem read: {} path(s)\n\
                   Filesystem write: {} path(s)\n\
                   Env vars allowed: {}\n\
                 \n\
                 Resources:\n\
                   Memory: {} MB\n\
                   Max runtime: {}s\n\
                 \n\
                 Seccomp profile: {}",
                m.skill.name,
                m.skill.version,
                m.entrypoint.command,
                m.entrypoint.args.join(" "),
                m.permissions.network.egress.len(),
                m.permissions.filesystem.read.len(),
                m.permissions.filesystem.write.len(),
                m.permissions
                    .env_vars
                    .allow
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                m.resources.memory_mb,
                m.resources.max_runtime_seconds,
                m.permissions.syscalls.profile,
            ),
            Err(e) => format!("✗ Invalid manifest at {:?}: {}", manifest_path, e),
        }
    }

    fn handle_list_skills(&self, req: ListSkillsRequest) -> String {
        let dir = PathBuf::from(&req.directory);

        if !dir.is_dir() {
            return format!("Error: Not a directory: {}", req.directory);
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => return format!("Error: Failed to read directory: {}", e),
        };

        let mut skills = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let manifest_path = path.join("skillsandbox.yaml");
                if manifest_path.exists() {
                    match SkillManifest::from_file(&manifest_path) {
                        Ok(m) => skills.push(format!(
                            "• {} v{} ({})\n\
                               Network: {} rule(s) | FS read: {} | FS write: {} | Env: {}",
                            m.skill.name,
                            m.skill.version,
                            path.display(),
                            m.permissions.network.egress.len(),
                            m.permissions.filesystem.read.len(),
                            m.permissions.filesystem.write.len(),
                            m.permissions.env_vars.allow.len(),
                        )),
                        Err(e) => skills.push(format!(
                            "• {} (invalid manifest: {})",
                            path.display(),
                            e
                        )),
                    }
                }
            }
        }

        if skills.is_empty() {
            format!("No skills found in: {}", req.directory)
        } else {
            format!(
                "Found {} skill(s) in {}:\n\n{}",
                skills.len(),
                req.directory,
                skills.join("\n\n"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// ServerHandler — manual trait implementation
//
// This avoids macro issues with rmcp 0.13's #[tool_router]/#[tool_handler]
// when tools need structured parameters.  We implement list_tools and
// call_tool directly, parsing JSON from the request.
// ---------------------------------------------------------------------------

impl ServerHandler for SkillSandboxMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "SkillSandbox MCP Server — capability-based sandbox runtime for AI agent skills. \
                 Skills declare required permissions (network endpoints, filesystem paths, env vars) \
                 in a skillsandbox.yaml manifest. The runtime enforces isolation: undeclared access \
                 is blocked via iptables, seccomp-bpf, mount namespaces, and env filtering. \
                 Every execution produces a structured audit trail."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListToolsResult {
            tools: Self::tool_definitions(),
            next_cursor: None,
            meta: None,
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            let args = request.arguments.unwrap_or_default();

            let text = match request.name.as_ref() {
                "run_skill" => {
                    let req: RunSkillRequest =
                        serde_json::from_value(serde_json::Value::Object(args)).map_err(|e| {
                            McpError {
                                code: ErrorCode::INVALID_PARAMS,
                                message: Cow::from(format!("Invalid parameters: {}", e)),
                                data: None,
                            }
                        })?;
                    self.handle_run_skill(req).await
                }
                "validate_skill" => {
                    let req: ValidateSkillRequest =
                        serde_json::from_value(serde_json::Value::Object(args)).map_err(|e| {
                            McpError {
                                code: ErrorCode::INVALID_PARAMS,
                                message: Cow::from(format!("Invalid parameters: {}", e)),
                                data: None,
                            }
                        })?;
                    self.handle_validate_skill(req)
                }
                "list_skills" => {
                    let req: ListSkillsRequest =
                        serde_json::from_value(serde_json::Value::Object(args)).map_err(|e| {
                            McpError {
                                code: ErrorCode::INVALID_PARAMS,
                                message: Cow::from(format!("Invalid parameters: {}", e)),
                                data: None,
                            }
                        })?;
                    self.handle_list_skills(req)
                }
                other => {
                    return Err(McpError {
                        code: ErrorCode::METHOD_NOT_FOUND,
                        message: Cow::from(format!("Unknown tool: {}", other)),
                        data: None,
                    });
                }
            };

            Ok(CallToolResult::success(vec![Content::text(text)]))
        }
    }
}
