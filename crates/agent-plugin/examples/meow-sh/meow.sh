#!/bin/sh
# on_response — append 喵～ to the assistant's final answer.
#
# stdin: {"event":"on_response","text":"<the answer>"}
# stdout verdict: {"action":"rewrite","text":"<new answer>"} / continue
#
# Demo-grade parsing: `text` is lifted with shell parameter expansion, which
# assumes a flat payload without escaped quotes — for real hooks use the
# Python/TS SDK (sdks/), they parse JSON properly.
payload=$(cat)
text=${payload#*\"text\":\"}
text=${text%\"\}}
[ -z "$text" ] && { echo '{"action":"continue"}'; exit 0; }
printf '{"action":"rewrite","text":"%s 喵～"}' "$text"
