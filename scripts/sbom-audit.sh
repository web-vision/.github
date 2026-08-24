#!/usr/bin/env bash
# sbom-audit.sh — reconcile the repository inventory against the Dependency-Track portfolio.
#
#   sbom-audit.sh --classified classified.jsonl [--out coverage.md] [--max-age-days 14]
#
# Answers the question a CRA auditor actually asks: "does every product you claim to cover have a
# current SBOM, and can you show me the ones that do not?"
#
# NOTE: /api/v1/project/concise enforces pagination and caps pageSize at 100 in Dependency-Track 5 —
# a v4-era script that assumes an unpaginated response silently truncates and over-reports coverage.
set -euo pipefail
CLASSIFIED=""; OUT="coverage.md"; MAXAGE=14
while [ $# -gt 0 ]; do
  case "$1" in
    --classified) CLASSIFIED="$2"; shift 2;; --out) OUT="$2"; shift 2;;
    --max-age-days) MAXAGE="$2"; shift 2;; *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$CLASSIFIED" ] || { echo "--classified required" >&2; exit 2; }
: "${DTRACK_API_URL:?}"; : "${DTRACK_API_KEY:?}"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
page=1; : > "$TMP/dt.jsonl"
while :; do
  res="$(curl --fail-with-body -sS -G "${DTRACK_API_URL%/}/api/v1/project/concise" \
        --header "X-Api-Key: ${DTRACK_API_KEY}" \
        --data "pageNumber=${page}" --data "pageSize=100")" || break
  n="$(jq 'length' <<<"$res")"; [ "$n" = "0" ] && break
  jq -c '.[]' <<<"$res" >> "$TMP/dt.jsonl"
  page=$((page+1)); [ "$page" -gt 200 ] && break
done
DTN=$(wc -l < "$TMP/dt.jsonl")

CUTOFF="$(date -u -d "-${MAXAGE} days" +%s000)"
jq -s 'map({key:.name, value:.}) | from_entries' "$TMP/dt.jsonl" > "$TMP/dt-index.json"

jq -r --slurpfile dt "$TMP/dt-index.json" --argjson cutoff "$CUTOFF" '
  select(.sbom_excluded|not)
  | (if (.composer_name // "") != "" then .composer_name else (.host+"/"+.path) end) as $n
  | ($dt[0][$n]) as $p
  | [ .path, .sbom_tier, .sbom_class, .sbom_cadence,
      (if $p == null then "MISSING"
       elif ((($p.lastBomImport // 0)|tonumber) < $cutoff) then "STALE"
       else "ok" end),
      (if $p == null then "-" else (($p.lastBomImport // 0)|tostring) end) ] | @tsv
' "$CLASSIFIED" > "$TMP/cov.tsv"

INSCOPE=$(wc -l < "$TMP/cov.tsv")
MISSING=$(awk -F'\t' '$5=="MISSING"' "$TMP/cov.tsv" | wc -l)
STALE=$(awk -F'\t' '$5=="STALE"' "$TMP/cov.tsv" | wc -l)
OKC=$(awk -F'\t' '$5=="ok"' "$TMP/cov.tsv" | wc -l)

{
  echo "# SBOM coverage — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "| | count |"
  echo "|---|---:|"
  echo "| repositories in scope | $INSCOPE |"
  echo "| current in Dependency-Track | $OKC |"
  echo "| stale (> ${MAXAGE} days) | $STALE |"
  echo "| missing entirely | $MISSING |"
  echo "| projects in Dependency-Track | $DTN |"
  echo
  echo "## Coverage by CRA tier"
  echo; echo "| tier | in scope | ok | stale | missing |"; echo "|---|---:|---:|---:|---:|"
  for t in A B C; do
    tot=$(awk -F'\t' -v t="$t" '$2==t' "$TMP/cov.tsv" | wc -l)
    o=$(awk -F'\t' -v t="$t" '$2==t && $5=="ok"' "$TMP/cov.tsv" | wc -l)
    s=$(awk -F'\t' -v t="$t" '$2==t && $5=="STALE"' "$TMP/cov.tsv" | wc -l)
    m=$(awk -F'\t' -v t="$t" '$2==t && $5=="MISSING"' "$TMP/cov.tsv" | wc -l)
    echo "| $t | $tot | $o | $s | $m |"
  done
  echo
  if [ "$MISSING" -gt 0 ]; then
    echo "## Missing"; echo; echo '```'
    awk -F'\t' '$5=="MISSING" {printf "%-58s %-3s %s\n", $1, $2, $3}' "$TMP/cov.tsv"
    echo '```'
  fi
  if [ "$STALE" -gt 0 ]; then
    echo "## Stale"; echo; echo '```'
    awk -F'\t' '$5=="STALE" {printf "%-58s %-3s %s\n", $1, $2, $3}' "$TMP/cov.tsv"
    echo '```'
  fi
} > "$OUT"

echo "[audit] in-scope=$INSCOPE ok=$OKC stale=$STALE missing=$MISSING -> $OUT" >&2
# Tier A is the legally required set; fail the pipeline only on a gap there.
TIERA_GAP=$(awk -F'\t' '$2=="A" && $5!="ok"' "$TMP/cov.tsv" | wc -l)
[ "$TIERA_GAP" -eq 0 ] || { echo "[audit] FAIL: $TIERA_GAP tier-A repositories lack a current SBOM" >&2; exit 1; }
