#!/usr/bin/env bash
# sbom-upload.sh — validate and upload one CycloneDX BOM to Dependency-Track.
#
#   sbom-upload.sh --bom <file> --project-name <name> --project-version <version>
#                  [--parent <name>] [--parent-version <v>] [--tags a,b,c]
#                  [--latest] [--archive-dir <dir>] [--dry-run]
#
# Requires: DTRACK_API_URL, DTRACK_API_KEY (API key needs BOM_UPLOAD + PROJECT_CREATION_UPLOAD).
#
# Guards implemented here, each for a measured reason:
#  1. version-less PURLs are rejected  - DT matches on the version INSIDE the purl and never on the
#     CycloneDX `version` field; such components are counted but never analysed (silent ballast).
#  2. --fail-with-body                 - plain `curl -sS` exits 0 on HTTP 4xx, hiding failed uploads.
#  3. durable archive copy             - DT does not retain uploaded BOM files; CRA requires 10 years
#                                        or the support period.
set -euo pipefail

BOM=""; PNAME=""; PVERSION=""; PARENT=""; PARENT_V=""; TAGS=""; LATEST=0; ARCHIVE=""; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bom) BOM="$2"; shift 2;;
    --project-name) PNAME="$2"; shift 2;;
    --project-version) PVERSION="$2"; shift 2;;
    --parent) PARENT="$2"; shift 2;;
    --parent-version) PARENT_V="$2"; shift 2;;
    --tags) TAGS="$2"; shift 2;;
    --latest) LATEST=1; shift;;
    --archive-dir) ARCHIVE="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$BOM" ] && [ -n "$PNAME" ] && [ -n "$PVERSION" ] || { echo "usage: see header" >&2; exit 2; }

die() { printf '[upload] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[upload] %s\n' "$*" >&2; }

# ---- guard 1: structural sanity ------------------------------------------------
jq -e '.bomFormat == "CycloneDX"' "$BOM" >/dev/null || die "$BOM is not a CycloneDX document"
SPEC="$(jq -r '.specVersion' "$BOM")"
case "$SPEC" in
  1.4|1.5|1.6) ;;
  1.7) die "specVersion 1.7 is rejected by Dependency-Track 5.0.4/4.14.3 — regenerate as 1.6";;
  *)   die "unexpected specVersion '$SPEC'";;
esac

TOTAL="$(jq '[.components[]?] | length' "$BOM")"
[ "$TOTAL" -gt 0 ] || die "$BOM contains zero components — refusing to upload a document that would
        create an empty Dependency-Track project and give false coverage"

# ---- guard 2: every purl must carry a version ----------------------------------
BAD="$(jq -r '[.components[]? | select((.purl // "") | test("@") | not) | (.name // "?")] | .[]' "$BOM")"
if [ -n "$BAD" ]; then
  BADN="$(printf '%s\n' "$BAD" | wc -l)"
  printf '%s\n' "$BAD" | head -20 >&2
  die "$BADN of $TOTAL components have a version-less PURL. Dependency-Track would count them and
        never analyse them. Fix the generator (or run purl-repair.jq) before uploading."
fi
log "$BOM: $TOTAL components, all PURLs versioned, spec $SPEC"

# ---- guard 3: durable archive --------------------------------------------------
if [ -n "$ARCHIVE" ]; then
  dest="$ARCHIVE/$(printf '%s' "$PNAME" | tr '/' '_')/$PVERSION"
  mkdir -p "$dest"
  cp "$BOM" "$dest/$(date -u +%Y%m%dT%H%M%SZ).cdx.json"
  log "archived to $dest"
fi

[ "$DRY" = 1 ] && { log "dry-run: not uploading"; exit 0; }

: "${DTRACK_API_URL:?DTRACK_API_URL is not configured}"
: "${DTRACK_API_KEY:?DTRACK_API_KEY is not configured}"

# ---- upload --------------------------------------------------------------------
set -- --fail-with-body --silent --show-error \
       --request POST "${DTRACK_API_URL%/}/api/v1/bom" \
       --header "X-Api-Key: ${DTRACK_API_KEY}" \
       --form "autoCreate=true" \
       --form "projectName=${PNAME}" \
       --form "projectVersion=${PVERSION}" \
       --form "bom=@${BOM}"
[ -n "$PARENT" ]   && set -- "$@" --form "parentName=${PARENT}"
[ -n "$PARENT_V" ] && set -- "$@" --form "parentVersion=${PARENT_V}"
[ -n "$TAGS" ]     && set -- "$@" --form "projectTags=${TAGS}"
# isLatest is honoured ONLY at project creation; existing projects are promoted below.
[ "$LATEST" = 1 ]  && set -- "$@" --form "isLatest=true"

RESP="$(curl "$@")" || die "upload failed: $RESP"
log "uploaded: $RESP"

# ---- promote to latest (optional) ----------------------------------------------
# BOM upload honours isLatest only when it CREATES the project, so an existing project has to be
# promoted explicitly with PATCH.
#
# Two things make this optional rather than routine:
#
#  1. isLatest is single-valued per project NAME — "at most one version per project name carries
#     the flag, and marking a new version as latest clears it on the previous one". For an extension
#     that emits one document per supported TYPO3 core, the variants are concurrent, not successive:
#     promoting main+typo3-13 and then main+typo3-14 would just demote the first, every run. There
#     is no meaningful "latest" among parallel core variants, so callers must not promote them.
#  2. PATCH /api/v1/project/{uuid} needs PORTFOLIO_MANAGEMENT_UPDATE. A least-privilege CI key
#     carrying only BOM_UPLOAD + PROJECT_CREATION_UPLOAD cannot do it, and should not: that
#     permission also allows deactivating and modifying any project. A 403 here is the expected
#     result of a correctly scoped CI key, not a fault.
#
# NOTE: Project.isLatest is a primitive boolean and PATCH skips only nulls — an omitted isLatest
# deserialises to false and WOULD DEMOTE the project. Always send it explicitly.
if [ "$LATEST" = 1 ]; then
  UUID="$(printf '%s' "$RESP" | jq -r '.projectUuid // empty')"
  if [ -z "$UUID" ]; then   # Dependency-Track 4.x does not return projectUuid on upload
    UUID="$(curl --fail-with-body -sS -G "${DTRACK_API_URL%/}/api/v1/project/lookup" \
              --header "X-Api-Key: ${DTRACK_API_KEY}" \
              --data-urlencode "name=${PNAME}" --data-urlencode "version=${PVERSION}" \
              2>/dev/null | jq -r '.uuid // empty')"
  fi
  if [ -n "$UUID" ]; then
    # Capture the status rather than letting curl print its own error: a 403 is an expected outcome
    # and should not look like a failure in the log.
    code="$(curl -sS -o /dev/null -w '%{http_code}' \
              --request PATCH "${DTRACK_API_URL%/}/api/v1/project/${UUID}" \
              --header "X-Api-Key: ${DTRACK_API_KEY}" \
              --header 'Content-Type: application/json' \
              --data '{"isLatest": true}' 2>/dev/null || true)"
    case "${code:-000}" in
      2*)  log "promoted ${PNAME}:${PVERSION} to latest" ;;
      403) log "not promoted to latest: this API key lacks PORTFOLIO_MANAGEMENT_UPDATE." \
               "That is expected for a least-privilege CI key — promotion is the reconciler's job." ;;
      404) log "not promoted to latest: project ${PNAME}:${PVERSION} not found (HTTP 404)" ;;
      000) log "not promoted to latest: Dependency-Track unreachable" ;;
      *)   log "not promoted to latest: unexpected HTTP ${code}" ;;
    esac
  else
    log "not promoted to latest: could not resolve project uuid"
  fi
fi
