#!/bin/bash
set -euo pipefail

INPUT=$(cat)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${BASE_DIR}/logs"
LOG_FILE="${LOG_DIR}/session-start.log"
mkdir -p "${LOG_DIR}"

SOURCE=$(echo "$INPUT" | jq -r '.source // "unknown"')
TIMESTAMP=$(echo "$INPUT" | jq -r '.timestamp // 0')

# Session start hook output is ignored; append a simple echo-based audit line.
echo "session_start source=${SOURCE} timestamp=${TIMESTAMP}" >> "$LOG_FILE"

exit 0
