#!/usr/bin/env bash
# Extension dependency law. Workspace-internal edges are tabled below; the only
# edges allowed INTO the kernel are the contract crates (agent-tool,
# agent-llm-core) — never the engine, never a product.
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A ALLOW=(
  [agent-sandbox]=""
  [agent-computer]=""
  [agent-paths]=""
  [agent-skills]=""
  [agent-plugin]="agent-llm-core agent-paths agent-sandbox"
  [agent-capabilities]="agent-computer agent-paths agent-sandbox agent-tool"
  [agent-tools-fs]="agent-capabilities agent-tool"
  [agent-tools-web]="agent-capabilities agent-llm-core agent-tool"
  [agent-tools-shell]="agent-capabilities agent-sandbox agent-tool"
  [agent-tools-computer]="agent-capabilities agent-computer agent-llm-core agent-paths agent-tool"
  [agent-tools-office]="agent-capabilities agent-sandbox agent-tool agent-tools-shell"
  [agent-tools-serena]="agent-capabilities agent-tool"
)
# Kernel crates an extension must never depend on.
KERNEL_FORBIDDEN=" agent-kernel agent-ipc agent-testkit "

meta=$(cargo metadata --no-deps --format-version 1)
fail=0
while IFS=$'\t' read -r name deps; do
  if [[ ! -v "ALLOW[$name]" ]]; then
    echo "FAIL  $name: not in the allowlist in scripts/check-deps.sh"; fail=1; continue
  fi
  for dep in $deps; do
    if [[ " ${ALLOW[$name]} " != *" $dep "* ]]; then
      echo "FAIL  $name -> $dep is not allowed (allowed: ${ALLOW[$name]:-none})"; fail=1
    fi
    if [[ "$KERNEL_FORBIDDEN" == *" $dep "* ]]; then
      echo "FAIL  $name -> $dep: extensions depend on the kernel's contracts only"; fail=1
    fi
  done
done < <(jq -r '
  ([.packages[].name] | unique) as $ws
  | .packages[]
  | [ .name,
      ([ .dependencies[]
         | select(.kind != "dev" and (.name | startswith("agent-")))
         | .name ] | unique | join(" ")) ]
  | @tsv' <<<"$meta")
[[ $fail -eq 0 ]] && echo "extension dependency law: ok"
exit $fail
