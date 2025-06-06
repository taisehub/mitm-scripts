#!/bin/zsh

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <reflector-target-domain> <js-tracker-domain(s)>"
  echo "Example: $0 facebook.com fbcdn.net"
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"

REFLECTOR_DOMAIN="$1"
JS_TRACKER_DOMAINS="$2"  # e.x. "fbcdn.net,cdn.facebook.com"

"${SCRIPT_DIR}/reflector" -domain "${REFLECTOR_DOMAIN}" &

REFLECTOR_PID=$!
trap "kill ${REFLECTOR_PID}; exit" SIGINT

mitmdump -q \
  -s "${SCRIPT_DIR}/js_tracker.py" \
  -s "${SCRIPT_DIR}/reflector.py" \
  --set "reflector_target=${REFLECTOR_DOMAIN}" \
  --set "js_tracker_domains=${JS_TRACKER_DOMAINS}" \
  -p 8081

