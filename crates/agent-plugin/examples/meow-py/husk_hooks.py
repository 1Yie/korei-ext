"""husk_hooks — write a husk plugin hook in Python.

The wire contract: the kernel spawns `run.command` once per intercepted
event, writes one JSON payload to stdin, and reads one JSON verdict from
stdout. This module hides all of that — register a handler per event and
return a verdict (or None to continue).

`guard.py` next to `manifest.json`:

    from husk_hooks import on, run, veto

    @on("before_tool_execute")
    def guard(p):
        if "push --force" in p["args"].get("command", ""):
            return veto("force-push needs a human")

    run()

manifest.json:

    {"id": "git-guard", "name": "Git Guard",
     "capabilities": {"hooks": [{
         "event": "before_tool_execute", "filter": {"tool": "bash"},
         "run": {"command": "python3", "args": ["guard.py"]}}]}}

Verdicts per event:
  on_user_input        continue | block(reason) | inject(note)
  before_tool_execute  continue | veto(reason)  | rewrite(args)
  after_tool_execute   continue | rewrite_output(output)
  on_state_transition  fire-and-forget — the verdict is ignored
  on_response          continue | rewrite_text(text) — mutates the final answer

Anything that isn't a clean verdict degrades to continue on the host:
exceptions print a traceback to stderr (captured in the hook log) and exit
with a continue verdict rather than breaking the turn.
"""

import json
import sys
import traceback

__all__ = [
    "on",
    "run",
    "cont",
    "block",
    "inject",
    "veto",
    "rewrite",
    "rewrite_output",
    "rewrite_text",
]

_REGISTRY = {}


# --- verdict helpers -------------------------------------------------------

def cont():
    return {"action": "continue"}


def block(reason):
    return {"action": "block", "reason": str(reason)}


def inject(note):
    return {"action": "inject", "note": str(note)}


def veto(reason):
    return {"action": "veto", "reason": str(reason)}


def rewrite(args):
    return {"action": "rewrite", "args": args}


def rewrite_output(output):
    return {"action": "rewrite_output", "output": str(output)}


def rewrite_text(text):
    return {"action": "rewrite", "text": str(text)}


# --- registration + dispatch ------------------------------------------------

def on(event):
    """Register the decorated function as the handler for one lifecycle
    event: on_user_input | before_tool_execute | after_tool_execute |
    on_state_transition | on_response. The handler receives the event
    payload dict — `input` for on_user_input, `tool`/`args` for the tool
    events (+ `output` for after_tool_execute), `old`/`new` for transitions,
    `text` for on_response."""

    def deco(fn):
        _REGISTRY[event] = fn
        return fn

    return deco


def run(stdin=None, stdout=None):
    """Read the payload, dispatch to its event's handler, print the verdict.
    Injectable streams keep this testable without subprocess plumbing."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    try:
        payload = json.loads(stdin.read())
    except Exception:
        # No payload means no event — continue is the only safe verdict.
        stdout.write(json.dumps(cont()))
        return
    handler = _REGISTRY.get(payload.get("event"))
    if handler is None:
        stdout.write(json.dumps(cont()))
        return
    try:
        verdict = handler(payload)
        if verdict is None:
            verdict = cont()
        stdout.write(json.dumps(verdict))
    except Exception:
        traceback.print_exc(file=sys.stderr)
        stdout.write(json.dumps(cont()))
