#!/usr/bin/env bash
# sbom-rescan.sh — regenerate the SBOM for a repository, optionally at an already-published tag.
#
#   # GitHub: dispatch the repository's own workflow against a tag
#   sbom-rescan.sh --host github.com --repo web-vision/deepltranslate-core --ref v1.2.3
#
#   # GitLab: run the central orchestrator for one repository at a tag
#   sbom-rescan.sh --host git.web-vision.io --repo extendware/m2/ew-affiliate-m2 --ref v1.2.3 \
#                  --orchestrator platform/sbom-orchestrator
#
#   --ref is optional; without it the default branch is regenerated.
#
# WHEN THIS IS WORTH DOING
#
# Dependency-Track already re-analyses the whole portfolio daily, so re-uploading an unchanged BOM
# discovers nothing. A rescan is meaningful when the RESOLUTION can move, which is exactly the case
# an incident raises:
#
#   * A package with no committed lock (most TYPO3 extensions, every Magento 2 module here) declares
#     constraints, not versions. "What does v1.2.3 install today?" has a different answer this week
#     than last, and that is the question during an incident - the published tag is unchanged, but
#     what a user gets when installing it is not.
#   * An application with a committed lock resolves to exactly one set of versions forever. Re-
#     running it produces a byte-identical BOM and tells you nothing new; Dependency-Track's own
#     re-analysis already covers it. Rescan those only to prove freshness, not to find anything.
#
# So: rescan lockless packages on an incident. For locked applications, read Dependency-Track.
set -euo pipefail
HOST=""; REPO=""; REF=""; ORCH="${SBOM_ORCHESTRATOR:-platform/sbom-orchestrator}"; WATCH=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2;; --repo) REPO="$2"; shift 2;;
    --ref) REF="$2"; shift 2;;   --orchestrator) ORCH="$2"; shift 2;;
    --watch) WATCH=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$HOST" ] && [ -n "$REPO" ] || { echo "usage: see header" >&2; exit 2; }

if [ "$HOST" = "github.com" ]; then
  # Dispatch from the default branch and pass the tag as an input. Dispatching AT the tag
  # (gh workflow run --ref v1.2.3) needs the workflow file to exist on that tag, which is false for
  # every release published before the workflow was added.
  echo "[rescan] dispatching sbom.yml on ${REPO}${REF:+ for ref ${REF}}"
  gh workflow run sbom.yml --repo "$REPO" ${REF:+--raw-field target_ref="$REF"}
  sleep 3
  run="$(gh run list --repo "$REPO" --workflow sbom.yml --limit 1 --json databaseId,url \
         | jq -r '.[0]')"
  echo "[rescan] $(printf '%s' "$run" | jq -r '.url')"
  if [ "$WATCH" = 1 ]; then
    gh run watch "$(printf '%s' "$run" | jq -r '.databaseId')" --repo "$REPO" --exit-status
  fi
else
  # Run the central orchestrator for just this repository. Works even when the repository has no CI,
  # no runner, or a tag that predates all SBOM tooling - the orchestrator clones the ref itself.
  echo "[rescan] triggering ${ORCH} on ${HOST} for ${REPO}${REF:+ at ${REF}}"
  glab ci run --repo "$ORCH" --hostname "$HOST" \
    --variables "SBOM_ONLY:${REPO}" ${REF:+--variables "SBOM_REF:${REF}"} \
    || {
      echo "[rescan] glab ci run failed; equivalent API call:" >&2
      echo "  curl --request POST --header \"PRIVATE-TOKEN: \$TOKEN\" \\" >&2
      echo "    \"https://${HOST}/api/v4/projects/\$(printf '%s' '${ORCH}' | jq -sRr @uri)/pipeline\" \\" >&2
      echo "    --form ref=main --form 'variables[][key]=SBOM_ONLY' --form 'variables[][value]=${REPO}'" >&2
      exit 1
    }
fi
