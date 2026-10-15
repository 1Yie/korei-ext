# korei-ext

Capabilities and tool packages for the [korei](../korei) kernel.

| layer | crates |
|---|---|
| capability contract | `agent-capabilities` (workspace paths, `SandboxCtx`, optional desktop) |
| backends | `agent-sandbox`, `agent-computer`, `agent-plugin`, `agent-paths` |
| tool packages | `agent-tools-fs`, `-web`, `-shell`, `-computer`, `-office`, `-serena` |

Tool packages are generic over the context (`agent-tool::ToolContext`); they
depend on the kernel's **contracts** (`agent-tool`, `agent-llm-core`) only —
never on `agent-kernel`. `scripts/check-deps.sh` enforces this.

## Layout

The kernel is resolved as a sibling checkout:

```
workspace/
  korei/
  korei-ext/
```

Kernel crates are declared once in `[workspace.dependencies]` here, so moving
to git or registry dependencies is a one-place change.
