#!/usr/bin/env bash
# Regenerate tests/vectors/nostr-vectors.json from the reference TypeScript SDK
# (@unicitylabs/nostr-js-sdk). Requires a checkout of that repo with deps installed.
#
# Usage: tools/regen-vectors.sh [path-to-nostr-js-sdk]   (default: ../nostr-js-sdk)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
JS_SDK="${1:-$HERE/../nostr-js-sdk}"

[ -d "$JS_SDK/node_modules" ] || { echo "error: run 'npm ci' in $JS_SDK first"; exit 1; }

cp "$HERE/tools/gen-vectors.test.ts" "$JS_SDK/tests/gen-vectors.test.ts"
trap 'rm -f "$JS_SDK/tests/gen-vectors.test.ts"' EXIT

( cd "$JS_SDK" && VECTORS_OUT="$HERE/tests/vectors/nostr-vectors.json" \
    npx vitest run tests/gen-vectors.test.ts )

echo "wrote $HERE/tests/vectors/nostr-vectors.json"
