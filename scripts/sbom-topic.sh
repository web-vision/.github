#!/usr/bin/env bash
# sbom-topic.sh — add or remove the `sbom` project topic in bulk, so onboarding is a data change
# rather than a pipeline change.
#
#   sbom-topic.sh --host git.example.com --token <PAT> --from repos.txt          # dry run
#   sbom-topic.sh --host git.example.com --token <PAT> --from repos.txt --apply
#   sbom-topic.sh --host git.example.com --token <PAT> --from repos.txt --remove --apply
#
#   --from <file>   newline-separated `namespace/project` paths, or "-" to read stdin
#   --topic <name>  topic to manage (default: sbom)
#   --apply         actually write. WITHOUT THIS THE SCRIPT ONLY REPORTS.
#   --remove        remove the topic instead of adding it
#
# The token needs `api` scope (write); a `read_api` token is enough for the dry run.
#
# Topics are edited through PUT /projects/:id with the FULL topics array, so this reads the current
# list and merges rather than overwriting — a project's existing topics (TYPO3, Extension, …) are
# preserved. Overwriting them would silently destroy classification other people rely on.
set -euo pipefail
HOST=""; TOKEN="${SBOM_WRITE_TOKEN:-${SBOM_READ_TOKEN:-}}"; FROM=""; TOPIC="sbom"; APPLY=0; REMOVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2;;   --token) TOKEN="$2"; shift 2;;
    --from) FROM="$2"; shift 2;;   --topic) TOPIC="$2"; shift 2;;
    --apply) APPLY=1; shift;;      --remove) REMOVE=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$HOST" ] && [ -n "$FROM" ] && [ -n "$TOKEN" ] || { echo "usage: see header" >&2; exit 2; }

# --location matters: GitLab answers a path-based project lookup
# (/projects/group%2Fproject) with a 301 to the numeric id (/projects/32), and the redirect body is
# plain text, not JSON. Without -L the response never parses.
api() { curl -fsSL --header "PRIVATE-TOKEN: ${TOKEN}" "$@"; }
enc() { printf '%s' "$1" | jq -sRr @uri; }

src="$FROM"; [ "$FROM" = "-" ] && src=/dev/stdin
changed=0; skipped=0; failed=0
while IFS= read -r path; do
  path="$(printf '%s' "$path" | tr -d '[:space:]')"
  [ -z "$path" ] && continue
  proj="$(api "https://${HOST}/api/v4/projects/$(enc "$path")" 2>/dev/null)" || {
    printf '  %-60s FAILED to read\n' "$path"; failed=$((failed+1)); continue; }
  cur="$(printf '%s' "$proj" | jq -c '.topics // []')"
  id="$(printf '%s' "$proj" | jq -r '.id')"
  has="$(printf '%s' "$cur" | jq --arg t "$TOPIC" 'index($t) != null')"
  if [ "$REMOVE" = 1 ]; then
    [ "$has" = "false" ] && { printf '  %-60s already absent\n' "$path"; skipped=$((skipped+1)); continue; }
    new="$(printf '%s' "$cur" | jq -c --arg t "$TOPIC" 'map(select(. != $t))')"
  else
    [ "$has" = "true" ]  && { printf '  %-60s already tagged\n' "$path"; skipped=$((skipped+1)); continue; }
    new="$(printf '%s' "$cur" | jq -c --arg t "$TOPIC" '. + [$t]')"
  fi
  if [ "$APPLY" = 1 ]; then
    if api --request PUT "https://${HOST}/api/v4/projects/${id}" \
         --header 'Content-Type: application/json' \
         --data "$(jq -cn --argjson t "$new" '{topics:$t}')" >/dev/null 2>&1; then
      printf '  %-60s %s -> %s\n' "$path" "$cur" "$new"; changed=$((changed+1))
    else
      printf '  %-60s WRITE FAILED (token needs api scope, and Maintainer on the project)\n' "$path"
      failed=$((failed+1))
    fi
  else
    printf '  %-60s would become %s\n' "$path" "$new"; changed=$((changed+1))
  fi
done < "$src"

echo
if [ "$APPLY" = 1 ]; then
  echo "[topic] changed=$changed skipped=$skipped failed=$failed"
else
  echo "[topic] DRY RUN - nothing was written. would-change=$changed skipped=$skipped failed=$failed"
  echo "[topic] re-run with --apply to write."
fi
