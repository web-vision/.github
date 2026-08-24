#!/usr/bin/env bash
# clica-export.sh — emit CISO Assistant (CLICA) perimeter + asset CSVs from the SBOM inventory.
#
#   clica-export.sh --classified classified.jsonl --domain "web-vision GmbH" [--out-dir .]
#
# The existing import-repos.sh / import-repos-gitlab.sh in wv-people/cra capture only
# name/description/url and cover one group at a time. This emits the same CSV contract from the
# richer inventory the SBOM programme already builds, so the asset register and the Dependency-Track
# portfolio cannot drift apart.
#
# Division of responsibility: Dependency-Track owns SBOMs and vulnerability data;
# CISO Assistant owns the compliance record, asset register and evidence.
set -euo pipefail
CLASSIFIED=""; DOMAIN=""; OUTDIR="."
while [ $# -gt 0 ]; do
  case "$1" in
    --classified) CLASSIFIED="$2"; shift 2;; --domain) DOMAIN="$2"; shift 2;;
    --out-dir) OUTDIR="$2"; shift 2;; *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$CLASSIFIED" ] && [ -n "$DOMAIN" ] || { echo "usage: see header" >&2; exit 2; }
mkdir -p "$OUTDIR"

P="$OUTDIR/repos-perimeters.csv"; A="$OUTDIR/repos-assets.csv"
echo "name,ref_id,description,domain" > "$P"
echo "name,ref_id,domain,type,reference_link" > "$A"

jq -r --arg d "$DOMAIN" '
  select(.sbom_excluded|not)
  | (if (.composer_name // "") != "" then .composer_name else (.host+"/"+.path) end) as $ref
  | [ (.path|split("/")|last), $ref,
      ((.composer_type // "repository") + " | CRA tier " + .sbom_tier
       + " | sbom " + .sbom_class + " | " + .sbom_cadence + " | " + .web_url),
      $d ] | @csv' "$CLASSIFIED" >> "$P"

jq -r --arg d "$DOMAIN" '
  select(.sbom_excluded|not)
  | (if (.composer_name // "") != "" then .composer_name else (.host+"/"+.path) end) as $ref
  | [ (.path|split("/")|last), $ref, $d, "SP", .web_url ] | @csv' "$CLASSIFIED" >> "$A"

echo "[clica] $(( $(wc -l < "$P") - 1 )) perimeters -> $P" >&2
echo "[clica] $(( $(wc -l < "$A") - 1 )) assets     -> $A" >&2
echo "[clica] import with: uv run clica.py import-perimeters --file $P --folder \"$DOMAIN\"" >&2
