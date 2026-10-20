#!/usr/bin/env bash
# Compile playbooks/ninjaone.yaml -> ninjaone/playbooks/playbooks.json.
#
# The JSON is a build artifact: FortiSOAR's playbook format is a graph of UUID
# routes and step-argument dicts that is unreviewable by hand and trivially
# corrupted by an edit. Author the YAML; regenerate the JSON.
#
# Needs the fsrpb compiler (github: fsr-playbook-framework). Teach it about this
# connector once, so the validator knows the 56 operations and their parameters
# and rejects a typo at compile time instead of at 3am in a live run:
#
#     fsrpb provision /path/to/connector-ninjaone/ninjaone
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRAMEWORK="${FSRPB_HOME:-$HOME/PycharmProjects/fsr-playbook-framework}"
SRC="$ROOT/playbooks/ninjaone.yaml"
OUT="$ROOT/ninjaone/playbooks/playbooks.json"

if [ ! -d "$FRAMEWORK" ]; then
  echo "fsrpb not found at $FRAMEWORK; set FSRPB_HOME to its checkout." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

echo "==> provisioning the connector into the fsrpb catalog"
( cd "$FRAMEWORK" && uv run fsrpb provision "$ROOT/ninjaone" --force >/dev/null )

echo "==> validating $SRC"
( cd "$FRAMEWORK" && uv run fsrpb validate "$SRC" )

echo "==> compiling to $OUT"
( cd "$FRAMEWORK" && uv run fsrpb compile "$SRC" -o "$OUT" )

python3 - "$OUT" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding='utf-8'))
for collection in doc.get('data', []):
    flows = collection.get('workflows') or []
    print(f"    {collection.get('name')}: {len(flows)} playbook(s)")
    for flow in flows:
        print(f"      - {flow.get('name')} ({len(flow.get('steps') or [])} steps)")
PY
echo "==> done"
