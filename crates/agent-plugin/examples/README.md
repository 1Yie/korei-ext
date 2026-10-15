# Hook examples

Three copies of the same demo plugin — append `喵～` to every model answer —
in each language the hook contract supports. A hook is just a spawned
command (JSON on stdin, verdict JSON on stdout), so any language works; the
SDK files vendored here (`husk_hooks.py`, `husk-hooks.ts`) hide the
protocol.

Install one by copying its directory into a plugins dir:

```sh
cp -r meow-py ~/.config/husk/plugins/meow        # loads at boot
cp -r meow-ts <repo>/.husk/plugins/meow-ts      # repo-local — needs 信任
# …then 重新加载 on the 插件 settings page.
```

| dir | runtime | `run.command` |
|---|---|---|
| `meow-sh/` | `/bin/sh` | `./meow.sh` (path-shaped → plugin dir) |
| `meow-py/` | `python3` | `python3 main.py` (bare name → PATH) |
| `meow-ts/` | `bun` (node/tsx too) | `bun main.ts` + `env.PATH` passthrough |

Notes:

- Hook children run **env-clear** — the child sees only declared `env`.
  `bun`/`node` live outside the default PATH (`/bin:/usr/bin`) on most
  machines, so `meow-ts` declares `"env": {"PATH": "env:PATH"}` to pass the
  host's PATH through. Secret-shaped names are refused.
- `tests/sdk_examples.rs` drives each example through the real wire
  contract — `cargo test -p agent-plugin`.
