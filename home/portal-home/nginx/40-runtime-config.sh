#!/bin/sh
set -eu

validate_origin() {
  value="$1"
  name="$2"
  if [ -n "$value" ] && ! printf '%s' "$value" | grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$'; then
    echo "Invalid public origin in $name" >&2
    exit 1
  fi
}

validate_origin "${API_BASE_URL:-}" API_BASE_URL
validate_origin "${PORTAL_URL:-}" PORTAL_URL

envsubst '${API_BASE_URL} ${PORTAL_URL}' < /opt/veltrix/runtime-config.template.js > /tmp/runtime-config.js
