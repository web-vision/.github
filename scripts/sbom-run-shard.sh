#!/usr/bin/env bash
# sbom-run-shard.sh — process one shard: clone shallow, generate, upload, record outcome.
#
#   sbom-run-shard.sh --shard shards/shard-3.jsonl [--archive-dir bom-archive] [--dry-run]
#
# A failure in one repository must never fail the shard: partial coverage that is *reported* is far
# more useful than an aborted run. Every repository ends up in the TSV report with an explicit
# status, and the audit stage reconciles that against Dependency-Track.
set -uo pipefail
SHARD=""; ARCHIVE=""; DRY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --shard) SHARD="$2"; shift 2;; --archive-dir) ARCHIVE="$2"; shift 2;;
    --dry-run) DRY="--dry-run"; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$SHARD" ] || { echo "--shard required" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
REPORT="sbom-report-$(basename "$SHARD" .jsonl).tsv"
printf 'repo\tclass\tstatus\tboms\tdetail\n' > "$REPORT"
mkdir -p sbom-output work

ok=0; failed=0; skipped=0
while IFS= read -r row; do
  [ -z "$row" ] && continue
  path="$(jq -r '.path' <<<"$row")"
  host="$(jq -r '.host' <<<"$row")"
  klass="$(jq -r '.sbom_class' <<<"$row")"
  branch="$(jq -r '.default_branch' <<<"$row")"
  cname="$(jq -r 'if (.composer_name // "") != "" then .composer_name else (.host+"/"+.path) end' <<<"$row")"
  tier="$(jq -r '.sbom_tier' <<<"$row")"

  if [ "$klass" = "none" ]; then
    printf '%s\t%s\tskipped\t0\tno manifest\n' "$path" "$klass" >> "$REPORT"; skipped=$((skipped+1)); continue
  fi

  wd="work/$(printf '%s' "$path" | tr '/' '_')"
  rm -rf "$wd"
  # Clone URL: CI job token for GitLab, gh for GitHub. Shallow, single branch.
  case "$host" in
    github.com) url="https://x-access-token:${GH_READ_TOKEN:-$GITHUB_TOKEN}@github.com/${path}.git";;
    *)          url="https://oauth2:${SBOM_READ_TOKEN}@${host}/${path}.git";;
  esac
  if ! git clone --depth 1 --branch "$branch" --quiet "$url" "$wd" 2>/dev/null; then
    printf '%s\t%s\tfailed\t0\tclone failed\n' "$path" "$klass" >> "$REPORT"; failed=$((failed+1)); continue
  fi

  version="$(git -C "$wd" describe --tags --abbrev=0 2>/dev/null || echo '0.0.0')"
  manifest="$(mktemp)"
  if ! "$HERE/sbom-generate.sh" --dir "$wd" --class "$klass" --name "$cname" \
        --version "$version" --out sbom-output > "$manifest" 2>"$manifest.err"; then
    printf '%s\t%s\tfailed\t0\tgenerate: %s\n' "$path" "$klass" \
      "$(tail -1 "$manifest.err" | tr '\t\n' '  ' | cut -c1-160)" >> "$REPORT"
    failed=$((failed+1)); rm -rf "$wd"; continue
  fi

  n=0; uploadfail=0
  while IFS="$(printf '\t')" read -r bom variant; do
    [ -z "$bom" ] && continue
    pver="$branch"; [ "$variant" != "default" ] && pver="${branch}+${variant}"
    if "$HERE/sbom-upload.sh" --bom "$bom" --project-name "$cname" --project-version "$pver" \
         --tags "host:${host},tier:${tier},class:${klass}" \
         ${ARCHIVE:+--archive-dir "$ARCHIVE"} --latest $DRY >/dev/null 2>&1; then
      n=$((n+1))
    else uploadfail=$((uploadfail+1)); fi
  done < "$manifest"

  if [ "$uploadfail" -gt 0 ]; then
    printf '%s\t%s\tpartial\t%d\t%d upload(s) failed\n' "$path" "$klass" "$n" "$uploadfail" >> "$REPORT"
    failed=$((failed+1))
  else
    printf '%s\t%s\tok\t%d\t\n' "$path" "$klass" "$n" >> "$REPORT"; ok=$((ok+1))
  fi
  rm -rf "$wd" "$manifest" "$manifest.err"
done < "$SHARD"

echo "[shard] ok=$ok failed=$failed skipped=$skipped -> $REPORT" >&2
# Exit 0 deliberately: the audit stage decides whether coverage is acceptable, not this loop.
exit 0
