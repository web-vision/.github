#!/usr/bin/env bash
# sbom-shard.sh — split the classified in-scope work list into N shards of comparable cost.
#   sbom-shard.sh --in classified.jsonl --shards 8 --cadence weekly --out-dir shards/
# Cost model: a resolve is far more expensive than reading a lock, and a dual-core matrix resolves
# once per supported core. Shards are filled round-robin over a cost-sorted list so that no single
# shard collects all the expensive repos (git.web-vision.io enforces a 3600s job timeout).
set -euo pipefail
IN=""; SHARDS=8; CADENCE="weekly"; OUTDIR="shards"
while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN="$2"; shift 2;; --shards) SHARDS="$2"; shift 2;;
    --cadence) CADENCE="$2"; shift 2;; --out-dir) OUTDIR="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$IN" ] || { echo "--in required" >&2; exit 2; }
mkdir -p "$OUTDIR"; rm -f "$OUTDIR"/shard-*.jsonl
# cadence weekly => weekly only; monthly => weekly+monthly; all => everything in scope
FILTER='select(.sbom_excluded|not)'
case "$CADENCE" in
  weekly)  FILTER="$FILTER | select(.sbom_cadence==\"weekly\")";;
  monthly) FILTER="$FILTER | select(.sbom_cadence==\"weekly\" or .sbom_cadence==\"monthly\")";;
  all)     ;;
  *) echo "unknown cadence: $CADENCE" >&2; exit 2;;
esac
jq -c "$FILTER | . + {_cost: (
        if .sbom_class==\"composer-resolve-matrix\" then 100
        elif .sbom_class==\"composer-resolve\" then 60
        elif .sbom_class==\"container-image\" then 120
        elif .sbom_class==\"composer-corelocks\" then 20
        else 10 end)}" "$IN" \
  | jq -s -c 'sort_by(-._cost)|to_entries[]' \
  | while IFS= read -r e; do
      i="$(jq -r '.key' <<<"$e")"
      jq -c '.value' <<<"$e" >> "$OUTDIR/shard-$(( (i % SHARDS) + 1 )).jsonl"
    done
for n in $(seq 1 "$SHARDS"); do
  f="$OUTDIR/shard-$n.jsonl"; [ -f "$f" ] || : > "$f"
  echo "[shard] $f: $(wc -l < "$f") repos, cost $(jq -s '[.[]._cost]|add // 0' "$f")" >&2
done
