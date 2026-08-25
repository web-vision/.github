#!/usr/bin/env bash
# sbom-inventory.sh — enumerate repositories on one host and emit the classifier's field contract.
#
#   sbom-inventory.sh --host git.example.com --token <PAT> --out inventory.jsonl
#   sbom-inventory.sh --host github.com --org web-vision --out inventory.jsonl
#
#   --membership           ONLY projects the token's user is a member of. Off by default.
#                          Leaving it off is deliberate: `membership=true` silently hides every
#                          project the user does not belong to. Measured on git.web-vision.io it
#                          returned 307 of 393 non-archived projects - 86 repositories, 22 %, absent
#                          from the inventory with no error and no warning. With an admin token the
#                          unfiltered query returns the whole instance.
#   --with-archived        include archived projects (default: exclude).
#
#   --topic <t>[,<t>...]   restrict the gather to repositories carrying these topics.
#                          Filtered server-side (GitLab `?topic=`, GitHub `--topic`), so it is far
#                          cheaper than enumerating everything, and it makes onboarding opt-in: tag
#                          a repository and it joins the next run.
#                          Multiple topics are ANDed. **Matching is case-sensitive on GitLab** —
#                          `topic=extension` returns nothing where `topic=Extension` returns 14.
#
# IMPORTANT: a topic-filtered gather is a SCAN scope, not an AUDIT scope. An untagged repository is
# then silently uncovered, which is precisely the gap a CRA coverage report has to surface. Run the
# audit against an UNFILTERED inventory (see sbom-central.yml, which produces both).
#
# Emits one JSON object per repository with the fields consumed by sbom-classify.jq.
# Uses only read APIs. Never clones.
#
# NOTE on last_commit: GitLab's `last_activity_at` is NOT a reliable proxy for real work — on
# git.web-vision.io it reflects a bulk platform migration (2020-08-01) for a large share of repos.
# The real last-commit date is fetched per project instead.
set -euo pipefail
HOST=""; TOKEN="${SBOM_READ_TOKEN:-}"; ORG=""; OUT="inventory.jsonl"; JOBS="${SBOM_JOBS:-8}"
TOPIC="${SBOM_TOPIC:-}"
MEMBERSHIP=0
ARCHIVED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2;; --token) TOKEN="$2"; shift 2;;
    --org) ORG="$2"; shift 2;;   --out) OUT="$2"; shift 2;;
    --topic) TOPIC="$2"; shift 2;;
    --membership) MEMBERSHIP=1; shift;;
    --with-archived) ARCHIVED=1; shift;;
    --jobs) JOBS="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$HOST" ] || { echo "--host required" >&2; exit 2; }
NOW6="$(date -u -d '-6 months' +%Y-%m-%d)"; NOW24="$(date -u -d '-24 months' +%Y-%m-%d)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

if [ "$HOST" = "github.com" ]; then
  [ -n "$ORG" ] || { echo "--org required for github.com" >&2; exit 2; }
  GH_TOPIC_ARGS=()
  if [ -n "$TOPIC" ]; then
    # gh accepts one --topic per flag; repeating them ANDs.
    IFS=',' read -ra _tl <<< "$TOPIC"
    for _t in "${_tl[@]}"; do GH_TOPIC_ARGS+=(--topic "$_t"); done
    echo "[inventory] restricting to topics: $TOPIC" >&2
  fi
  gh repo list "$ORG" --limit 1000 "${GH_TOPIC_ARGS[@]}" --json \
    name,nameWithOwner,isArchived,isPrivate,isFork,defaultBranchRef,pushedAt,repositoryTopics,url \
    | jq -c '.[]' > "$TMP/raw.jsonl"
  probe_github() {
    local nwo="$1" br="$2"
    local tree; tree="$(gh api "repos/${nwo}/git/trees/${br}?recursive=1" 2>/dev/null || echo '{}')"
    local paths; paths="$(printf '%s' "$tree" | jq -r '[.tree[]?|select(.type=="blob")|.path]|@json')"
    local cj=""; case "$paths" in *'"composer.json"'*) cj="$(gh api "repos/${nwo}/contents/composer.json?ref=${br}" -H 'Accept: application/vnd.github.raw' 2>/dev/null || echo '{}')";; esac
    printf '%s\t%s\n' "$paths" "$(printf '%s' "$cj" | jq -c '.' 2>/dev/null || echo '{}')"
  }
  export -f probe_github
  : > "$OUT"
  while IFS= read -r row; do
    nwo="$(jq -r '.nameWithOwner' <<<"$row")"; br="$(jq -r '.defaultBranchRef.name // ""' <<<"$row")"
    if [ -z "$br" ]; then paths='[]'; cj='{}'; else
      IFS=$'\t' read -r paths cj < <(probe_github "$nwo" "$br"); fi
    jq -cn --argjson r "$row" --argjson paths "${paths:-[]}" --argjson cj "${cj:-{\}}" \
      --arg m6 "$NOW6" --arg m24 "$NOW24" '
      {host:"github.com", path:$r.nameWithOwner, default_branch:($r.defaultBranchRef.name // ""),
       visibility:(if $r.isPrivate then "private" else "public" end),
       archived:$r.isArchived, is_fork:$r.isFork, last_commit:($r.pushedAt // ""),
       topics:[$r.repositoryTopics[]?.name], web_url:$r.url,
       composer_name:($cj.name // ""), composer_type:($cj.type // ""),
       typo3_core:($cj.require["typo3/cms-core"] // ""),
       dual_core:((($cj.require["typo3/cms-core"] // "")|test("\\|\\|")) // false),
       has_lock:($paths|index("composer.lock")!=null),
       core_locks:[$paths[]?|select(test("^core-?[0-9]+/composer\\.lock$"))],
       has_package_json:($paths|index("package.json")!=null),
       builds_image:([$paths[]?|select(test("(^|/)Dockerfile"))]|length>0),
       magento1_tree:([$paths[]?|select(test("app/etc/modules/.*\\.xml$"))]|length>0),
       vendor_installed_php:([$paths[]?|select(test("^vendor/composer/installed\\.php$"))]|length>0),
       root_files:[$paths[]?|select(test("/")|not)],
       now_minus_6m:$m6, now_minus_24m:$m24}' >> "$OUT"
  done < "$TMP/raw.jsonl"
else
  # ---- GitLab ----
  api() { curl -fsS --header "PRIVATE-TOKEN: ${TOKEN}" "https://${HOST}/api/v4/$1"; }
  export -f api; export HOST TOKEN
  page=1; : > "$TMP/projects.jsonl"
  while :; do
    q="per_page=100&page=${page}&order_by=id&sort=asc"
    [ "$MEMBERSHIP" = 1 ] && q="${q}&membership=true"
    [ "$ARCHIVED" = 0 ] && q="${q}&archived=false"
    [ -n "$TOPIC" ] && q="${q}&topic=${TOPIC}"
    res="$(api "projects?${q}")"
    n="$(jq 'length' <<<"$res")"; [ "$n" = "0" ] && break
    jq -c '.[]' <<<"$res" >> "$TMP/projects.jsonl"; page=$((page+1)); [ "$page" -gt 50 ] && break
  done
  probe_gitlab() {
    local id="$1" br="$2"
    local tree; tree="$(api "projects/${id}/repository/tree?ref=${br}&per_page=100" 2>/dev/null || echo '[]')"
    local names; names="$(jq -r '[.[]?|.name]|@json' <<<"$tree")"
    local lc; lc="$(api "projects/${id}/repository/commits?ref_name=${br}&per_page=1" 2>/dev/null | jq -r '.[0].committed_date // ""')"
    local cj='{}'
    case "$names" in *'"composer.json"'*) cj="$(api "projects/${id}/repository/files/composer%2Ejson/raw?ref=${br}" 2>/dev/null | jq -c '.' 2>/dev/null || echo '{}')";; esac
    printf '%s\t%s\t%s\n' "$names" "$lc" "$cj"
  }
  export -f probe_gitlab
  : > "$OUT"
  while IFS= read -r row; do
    id="$(jq -r '.id' <<<"$row")"; br="$(jq -r '.default_branch // ""' <<<"$row")"
    if [ -z "$br" ]; then names='[]'; lc=''; cj='{}'; else
      IFS=$'\t' read -r names lc cj < <(probe_gitlab "$id" "$br"); fi
    jq -cn --argjson r "$row" --argjson names "${names:-[]}" --arg lc "${lc:-}" \
      --argjson cj "${cj:-{\}}" --arg m6 "$NOW6" --arg m24 "$NOW24" --arg host "$HOST" '
      {host:$host, path:$r.path_with_namespace, default_branch:($r.default_branch // ""),
       visibility:$r.visibility, archived:$r.archived, is_fork:($r.forked_from_project != null),
       last_commit:$lc, topics:($r.topics // []), web_url:$r.web_url,
       jobs_enabled:$r.jobs_enabled, shared_runners:$r.shared_runners_enabled,
       composer_name:($cj.name // ""), composer_type:($cj.type // ""),
       typo3_core:($cj.require["typo3/cms-core"] // ""),
       dual_core:((($cj.require["typo3/cms-core"] // "")|test("\\|\\|")) // false),
       has_lock:($names|index("composer.lock")!=null),
       has_package_json:($names|index("package.json")!=null),
       builds_image:($names|index("Dockerfile")!=null),
       magento1_tree:(($names|index("app")!=null) and ($names|index("composer.json")==null)),
       root_files:$names, core_locks:[],
       is_mirror:(($r.path_with_namespace|test("mirror")) or ($r.import_url != null)),
       now_minus_6m:$m6, now_minus_24m:$m24}' >> "$OUT"
  done < "$TMP/projects.jsonl"
fi
echo "[inventory] wrote $(wc -l < "$OUT") repositories to $OUT${TOPIC:+ (topics: $TOPIC)}" >&2
if [ -n "$TOPIC" ] && [ ! -s "$OUT" ]; then
  echo "[inventory] WARNING: topic filter '$TOPIC' matched nothing. GitLab topic matching is" >&2
  echo "[inventory] case-sensitive; check the exact spelling in the project settings." >&2
fi
