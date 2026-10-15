# korei-ext

Tools and capabilities for the [korei](https://github.com/1Yie/korei) agent
kernel.

| crate | what it is |
|---|---|
| `agent-tools-fs` | read, search and edit files in a workspace |
| `agent-tools-shell` | run commands and keep background services up |
| `agent-tools-web` | fetch and search the web |
| `agent-tools-office` | work with office documents |
| `agent-tools-computer` | drive a desktop through screenshots and input |
| `agent-tools-serena` | bridge to a Serena MCP server |
| `agent-sandbox` | run commands under bubblewrap, Landlock, seatbelt or a Windows job |
| `agent-plugin` | load hook and WASM plugins |
| `agent-computer` | desktop capture and input backends |
| `agent-capabilities` | the traits tool packages are written against |
| `agent-paths` | where an app keeps its files |

Tool packages depend only on korei's contracts (`agent-tool`, `agent-llm-core`),
never on the engine, so they work with any host.

## License

MIT
