/**
 * Demo hook — appends 喵～ to the end of every model answer.
 *
 * `husk-hooks.ts` next to this file is vendored from `<repo>/sdks/ts/` —
 * copy it along when installing the plugin into a plugins dir.
 *
 * Note the manifest's `env.PATH: "env:PATH"`: hook children run env-clear
 * (declared env only), and `bun`/`node` live outside the default PATH on
 * most machines — the indirection passes the host PATH through so the
 * runtime resolves.
 */

import { on, rewriteText, run } from "./husk-hooks";

on("on_response", (p) => {
  const text = (p.text ?? "").trimEnd();
  if (text && !text.endsWith("喵～")) return rewriteText(`${text} 喵～`);
});

await run();
