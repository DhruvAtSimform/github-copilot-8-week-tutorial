#!/bin/bash
set -euo pipefail

INPUT=$(cat)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${BASE_DIR}/logs"
LOG_FILE="${LOG_DIR}/pre-tool-use.jsonl"
mkdir -p "${LOG_DIR}"

TOOL_NAME=$(echo "$INPUT" | jq -r '.toolName // "unknown"')
TIMESTAMP=$(echo "$INPUT" | jq -r '.timestamp // 0')
CWD_VAL=$(echo "$INPUT" | jq -r '.cwd // ""')
TOOL_ARGS=$(echo "$INPUT" | jq -c '.toolArgs // ""')

jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg cwd "$CWD_VAL" \
  --arg toolName "$TOOL_NAME" \
  --argjson toolArgs "$TOOL_ARGS" \
  '{timestamp: $timestamp, cwd: $cwd, toolName: $toolName, toolArgs: $toolArgs}' >> "$LOG_FILE"

# if [ "$TOOL_NAME" = "bash" ] || [ "$TOOL_NAME" = "edit" ]; then
#   jq -cn \
#     --arg reason "Denied by preToolUse policy: tool '$TOOL_NAME' is blocked" \
#     '{permissionDecision: "deny", permissionDecisionReason: $reason}'
#   exit 0
# fi

# exit 0
