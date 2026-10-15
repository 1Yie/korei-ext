/**
 * husk-hooks — write a husk plugin hook in TypeScript/JavaScript.
 *
 * The wire contract: the kernel spawns `run.command` once per intercepted
 * event, writes one JSON payload to stdin, and reads one JSON verdict from
 * stdout. This module hides all of that — register a handler per event and
 * return a verdict (or undefined to continue).
 *
 * `guard.ts` next to `manifest.json`:
 *
 *   import { on, run, veto } from "./husk-hooks";
 *
 *   on("before_tool_execute", (p) =>
 *     p.args?.command?.includes("push --force")
 *       ? veto("force-push needs a human")
 *       : undefined,
 *   );
 *
 *   await run();
 *
 * manifest.json:
 *
 *   {"id": "git-guard", "name": "Git Guard",
 *    "capabilities": {"hooks": [{
 *        "event": "before_tool_execute", "filter": {"tool": "bash"},
 *        "run": {"command": "bun", "args": ["guard.ts"]}}]}}
 *
 * Verdicts per event:
 *   on_user_input        continue | block(reason) | inject(note)
 *   before_tool_execute  continue | veto(reason)  | rewrite(args)
 *   after_tool_execute   continue | rewriteOutput(output)
 *   on_state_transition  fire-and-forget — the verdict is ignored
 *   on_response          continue | rewriteText(text) — mutates the final answer
 *
 * Anything that isn't a clean verdict degrades to continue on the host:
 * a thrown handler logs to stderr (captured in the hook log) and exits with
 * a continue verdict rather than breaking the turn.
 *
 * Zero deps, no Node typings required — runs under bun, node and tsx.
 */

/** The stdin payload — fields depend on `event`. */
export interface HookPayload {
  event: "on_user_input" | "before_tool_execute" | "after_tool_execute" | "on_state_transition" | string;
  /** on_user_input */
  input?: string;
  /** before_tool_execute / after_tool_execute */
  tool?: string;
  args?: Record<string, unknown>;
  /** after_tool_execute */
  output?: string;
  /** on_state_transition */
  old?: string;
  new?: string;
  /** on_response — the assistant's final answer text. */
  text?: string;
}

export type Verdict = Record<string, unknown>;
export type Handler = (payload: HookPayload) => Verdict | undefined | Promise<Verdict | undefined>;

/* eslint-disable @typescript-eslint/no-explicit-any */
declare const process: any;

// --- verdict helpers -------------------------------------------------------

export const cont = (): Verdict => ({ action: "continue" });
export const block = (reason: unknown): Verdict => ({ action: "block", reason: String(reason) });
export const inject = (note: unknown): Verdict => ({ action: "inject", note: String(note) });
export const veto = (reason: unknown): Verdict => ({ action: "veto", reason: String(reason) });
export const rewrite = (args: Record<string, unknown>): Verdict => ({ action: "rewrite", args });
export const rewriteOutput = (output: unknown): Verdict => ({
  action: "rewrite_output",
  output: String(output),
});
export const rewriteText = (text: unknown): Verdict => ({ action: "rewrite", text: String(text) });

// --- registration + dispatch ------------------------------------------------

const registry = new Map<string, Handler>();

/** Register `handler` for one lifecycle event. */
export function on(event: HookPayload["event"], handler: Handler): void {
  registry.set(event, handler);
}

async function readStdin(): Promise<string> {
  // Bun exposes a fast path; Node's stream API works everywhere else.
  const bun = (globalThis as Record<string, any>).Bun;
  if (bun?.stdin) return await bun.stdin.text();
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

/** Read the payload, dispatch to its event's handler, print the verdict. */
export async function run(): Promise<void> {
  let payload: HookPayload;
  try {
    payload = JSON.parse(await readStdin());
  } catch {
    process.stdout.write(JSON.stringify(cont()));
    return;
  }
  const handler = registry.get(payload?.event ?? "");
  if (!handler) {
    process.stdout.write(JSON.stringify(cont()));
    return;
  }
  try {
    const verdict = (await handler(payload)) ?? cont();
    process.stdout.write(JSON.stringify(verdict));
  } catch (e) {
    process.stderr.write(String(e?.stack ?? e) + "\n");
    process.stdout.write(JSON.stringify(cont()));
  }
}
