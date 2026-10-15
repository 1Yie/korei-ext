//! Serena's `tools/list`, cached per bridge.
//!
//! Two jobs: stop paying a round trip for every discovery call, and give the
//! model enough to *use* a tool without guessing. A bare list of 40 names is
//! an API it has to reverse-engineer, so the rendering includes each tool's
//! argument names (required marked `*`) and can print one tool's full JSON
//! Schema on request.

use serde_json::Value;

use super::bridge::{McpBridge, SerenaToolInfo};
use agent_tool::ToolError;

#[derive(Debug, Default)]
pub struct SerenaToolCatalog {
    tools: Vec<SerenaToolInfo>,
    fetched: bool,
}

impl SerenaToolCatalog {
    /// The server's tool list, fetched once per bridge. A restarted bridge
    /// gets a fresh catalog because the manager drops the whole slot.
    pub async fn tools(&mut self, bridge: &dyn McpBridge) -> Result<&[SerenaToolInfo], ToolError> {
        if !self.fetched {
            self.tools = bridge.list_tools().await?;
            self.fetched = true;
        }
        Ok(&self.tools)
    }

    /// Compact rendering for the model: one line per tool plus its argument
    /// names. Full schemas stay one call away (`detail`), because dumping
    /// ~40 of them would be the tool-context bloat the meta-tool exists to
    /// avoid.
    pub fn render(&self, detail: Option<&str>) -> String {
        if let Some(name) = detail {
            return match self.tools.iter().find(|t| t.name == name) {
                Some(t) => {
                    let schema = t
                        .input_schema
                        .clone()
                        .unwrap_or_else(|| Value::Object(Default::default()));
                    format!(
                        "{}\n\n{}\n\ninputSchema:\n{}",
                        t.name,
                        t.description
                            .as_deref()
                            .unwrap_or("(no description)")
                            .trim(),
                        serde_json::to_string_pretty(&schema).unwrap_or_default()
                    )
                }
                None => format!(
                    "No serena tool named `{name}`. Available: {}",
                    self.tools
                        .iter()
                        .map(|t| t.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
        }
        if self.tools.is_empty() {
            return "No serena tools reported by the server.".into();
        }
        let mut out = format!(
            "{} serena tools. Call one with `tool` + `arguments`; `{DETAIL_ACTION}` \
             with {{name}} prints its full schema.\n",
            self.tools.len()
        );
        for t in &self.tools {
            let summary = t
                .description
                .as_deref()
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("")
                .trim();
            out.push_str(&format!("• {} — {summary}\n", t.name));
            if let Some(args) = argument_summary(t.input_schema.as_ref()) {
                out.push_str(&format!("  args: {args}\n"));
            }
        }
        out.trim_end().to_string()
    }
}

/// The pseudo-tool name that prints one tool's schema.
pub const DETAIL_ACTION: &str = "serena_list_tools";

/// `name*` for required, `name` for optional — the model needs to know which
/// it must pass, and a full schema per tool is too much text for a list.
fn argument_summary(schema: Option<&Value>) -> Option<String> {
    let schema = schema?;
    let props = schema.get("properties")?.as_object()?;
    if props.is_empty() {
        return None;
    }
    let required: Vec<&str> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let mut parts: Vec<String> = Vec::new();
    for (name, spec) in props {
        let ty = spec.get("type").and_then(|t| t.as_str()).unwrap_or("any");
        parts.push(if required.contains(&name.as_str()) {
            format!("{name}*:{ty}")
        } else {
            format!("{name}:{ty}")
        });
    }
    Some(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(name: &str, props: Value, required: Value) -> SerenaToolInfo {
        SerenaToolInfo {
            name: name.into(),
            description: Some("First line.\nSecond line.".into()),
            input_schema: Some(json!({"type":"object","properties":props,"required":required})),
        }
    }

    #[test]
    fn render_marks_required_arguments_and_hides_extra_description_lines() {
        let cat = SerenaToolCatalog {
            fetched: true,
            tools: vec![tool(
                "find_symbol",
                json!({"name_path": {"type":"string"}, "depth": {"type":"integer"}}),
                json!(["name_path"]),
            )],
        };
        let out = cat.render(None);
        assert!(out.contains("find_symbol"), "{out}");
        assert!(out.contains("name_path*:string"), "{out}");
        assert!(out.contains("depth:integer"), "{out}");
        assert!(
            !out.contains("Second line"),
            "list stays one line per tool: {out}"
        );

        // Detail mode prints the schema for exactly one tool.
        let detail = cat.render(Some("find_symbol"));
        assert!(detail.contains("inputSchema"));
        assert!(detail.contains("\"name_path\""));
        let missing = SerenaToolCatalog::default().render(Some("nope"));
        assert!(missing.contains("No serena tool named"));
    }
}
