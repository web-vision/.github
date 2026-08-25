#!/usr/bin/env bash
# sbom-repolist.sh — emit one editable repository list per host, for script-driven onboarding.
#
#   sbom-repolist.sh --in classified.jsonl --out-dir deploy/repos
#   sbom-repolist.sh --in classified.jsonl --out-dir deploy/repos --by-group
#
# --by-group writes one file per group, under <out-dir>/<host>/<group>.txt with `/` replaced by `-`,
# plus a _GROUPS.txt index. Useful when onboarding is delegated per team, or when a whole group is to
# be excluded at once. On github.com, which has no nested groups, one file per organisation.
#
# --groups <file>  JSON Lines from GET /groups?all_available=true (one object per line, needs
#                  .full_path). Optional but recommended: it makes the listing AUTHORITATIVE rather
#                  than merely derived. A group whose repositories are all empty, archived or
#                  invisible has no rows in the inventory and would otherwise not appear at all -
#                  which is the same class of blind spot as filtering by membership. With this file
#                  such groups are emitted as empty, explicitly labelled, so they get reviewed
#                  instead of silently skipped. Namespaces holding projects but absent from the file
#                  are user namespaces and are labelled as such.
#
# Produces deploy/repos/<host>.txt: one repository path per line, annotated with the facts needed to
# decide whether it should be onboarded. Everything after `#` is a comment, so the files are both
# readable and directly consumable by the deploy scripts.
#
# The intended workflow is deliberately manual at the decision point: regenerate the list, delete or
# comment out what should not be onboarded, then run deploy/apply-topics.sh. Onboarding is a data
# change on the project (the `sbom` topic), so the list is the record of what was decided and why.
#
# Repositories excluded by the classifier are emitted commented-out with the reason, rather than
# omitted — an invisible exclusion is one nobody reviews.
set -euo pipefail
# NB: GROUPFILE, not GROUPS. GROUPS is a bash special variable holding the current user's group
# IDs; assigning to it silently does not stick and "$GROUPS" then expands to the primary GID, so a
# --groups argument would be read as "1000" and quietly ignored.
IN=""; OUTDIR="deploy/repos"; INCEXC=1; BYGROUP=0; GROUPFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN="$2"; shift 2;; --out-dir) OUTDIR="$2"; shift 2;;
    --no-excluded) INCEXC=0; shift;;
    --by-group) BYGROUP=1; shift;;
    --groups) GROUPFILE="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$IN" ] || { echo "--in <classified.jsonl> required" >&2; exit 2; }
mkdir -p "$OUTDIR"
STAMP="$(date -u +%Y-%m-%d)"

for host in $(jq -r '.host' "$IN" | sort -u); do
  # github.com holds two orgs; split them into separate files.
  if [ "$host" = "github.com" ]; then
    orgs="$(jq -r --arg h "$host" 'select(.host==$h)|.path|split("/")[0]' "$IN" | sort -u)"
  else
    orgs="-"
  fi
  for org in $orgs; do
    if [ "$org" = "-" ]; then
      file="$OUTDIR/${host}.txt"; label="$host"
      filter='select(.host==$h)'
    else
      file="$OUTDIR/${host}-${org}.txt"; label="$host/$org"
      filter='select(.host==$h) | select((.path|split("/")[0])==$o)'
    fi
    {
      echo "# $label — repositories considered for SBOM onboarding"
      echo "# Generated $STAMP by proposal/scripts/sbom-repolist.sh"
      echo "#"
      echo "# One repository path per line. Delete or comment out anything that should NOT be"
      echo "# onboarded, then apply with:"
      echo "#     proposal/deploy/apply-topics.sh --host $host --list $(basename "$file")"
      echo "#"
      echo "# Lines already commented carry the classifier's reason for excluding them. Uncomment"
      echo "# one to override that decision — the \`sbom\` topic beats every exclusion rule."
      echo "#"
      echo "# columns: path  |  class  |  cadence  |  tier  |  last commit"
      echo "#"
      jq -r --arg h "$host" --arg o "$org" "
        $filter
        | select(.sbom_excluded | not)
        | [ .path, .sbom_class, .sbom_cadence, .sbom_tier, ((.last_commit // \"\")[0:10]) ]
        | @tsv" "$IN" \
        | sort | awk -F'\t' '{printf "%-58s # %-26s %-9s %-2s %s\n", $1, $2, $3, $4, $5}'
      if [ "$INCEXC" = 1 ]; then
        echo
        echo "# ---- excluded by the classifier; uncomment to force onboarding ----"
        jq -r --arg h "$host" --arg o "$org" "
          $filter
          | select(.sbom_excluded)
          | [ .path, .sbom_exclude_reason, ((.last_commit // \"\")[0:10]) ]
          | @tsv" "$IN" \
          | sort | awk -F'\t' '{printf "#%-57s # %-40s %s\n", $1, $2, $3}'
      fi
    } > "$file"
    active=$(grep -cvE '^[[:space:]]*(#|$)' "$file" || true)
    echo "[repolist] $file: $active active, $(grep -c '^#[a-z]' "$file" || true) excluded" >&2
  done
done

# --- per group / subgroup ----------------------------------------------------------------------
if [ "$BYGROUP" = 1 ]; then
  for host in $(jq -r '.host' "$IN" | sort -u); do
    hdir="$OUTDIR/$host"; mkdir -p "$hdir"
    idx="$hdir/_GROUPS.txt"

    # Namespaces that actually hold inventoried repositories.
    jq -r --arg h "$host" 'select(.host==$h)|.namespace // ""' "$IN" | grep -v '^$' | sort -u \
      > "$hdir/.ns.derived"
    # Authoritative group list, when one was supplied for this host.
    : > "$hdir/.ns.declared"
    if [ -n "$GROUPFILE" ] && [ -f "$GROUPFILE" ] && [ "$host" != "github.com" ]; then
      jq -r 'select(.full_path != null)|.full_path' "$GROUPFILE" | sort -u > "$hdir/.ns.declared"
    fi
    sort -u "$hdir/.ns.derived" "$hdir/.ns.declared" > "$hdir/.ns.all"

    {
      echo "# $host — groups and namespaces"
      echo "# Generated $STAMP by proposal/scripts/sbom-repolist.sh --by-group"
      echo "#"
      if [ "$host" = "github.com" ]; then
        echo "# GitHub has organisations, not nested groups: one file per organisation."
      else
        echo "# One file per group and subgroup. Delete a file to leave that group un-onboarded."
      fi
      if [ -s "$hdir/.ns.declared" ]; then
        echo "# Group list taken from the instance API, so groups holding no inventoried"
        echo "# repository still appear - empty, archived or invisible repositories included."
      fi
      echo "#"
      printf "# %-42s %7s %6s  %-38s %s\n" "group" "inscope" "excl" "file" "note"
    } > "$idx"

    while IFS= read -r grp; do
      [ -z "$grp" ] && continue
      safe="$(printf '%s' "$grp" | tr '/' '-')"
      f="$hdir/${safe}.txt"
      note=""
      if [ -s "$hdir/.ns.declared" ]; then
        grep -qxF "$grp" "$hdir/.ns.declared" || note="user namespace"
      fi
      grep -qxF "$grp" "$hdir/.ns.derived" || note="${note:+$note, }no inventoried repositories"
      {
        echo "# $host : $grp"
        echo "# Generated $STAMP by proposal/scripts/sbom-repolist.sh --by-group"
        [ -n "$note" ] && echo "# NOTE: $note"
        echo "#"
        echo "# Apply with:"
        echo "#     proposal/deploy/apply-topics.sh --host $host --list $host/${safe}.txt --apply"
        echo "#"
        echo "# columns: path  |  class  |  cadence  |  tier  |  last commit"
        echo "#"
        jq -r --arg h "$host" --arg g "$grp" '
          select(.host==$h) | select((.namespace // "")==$g)
          | select(.sbom_excluded | not)
          | [ .path, .sbom_class, .sbom_cadence, .sbom_tier, ((.last_commit // "")[0:10]) ] | @tsv' "$IN" \
          | sort | awk -F'\t' '{printf "%-58s # %-26s %-9s %-2s %s\n", $1, $2, $3, $4, $5}'
        echo
        echo "# ---- excluded by the classifier; uncomment to force onboarding ----"
        jq -r --arg h "$host" --arg g "$grp" '
          select(.host==$h) | select((.namespace // "")==$g)
          | select(.sbom_excluded)
          | [ .path, .sbom_exclude_reason, ((.last_commit // "")[0:10]) ] | @tsv' "$IN" \
          | sort | awk -F'\t' '{printf "#%-57s # %-40s %s\n", $1, $2, $3}'
      } > "$f"
      a=$(grep -cvE '^[[:space:]]*(#|$)' "$f" || true)
      e=$(grep -c '^#[a-zA-Z0-9]' "$f" || true)
      printf "  %-42s %7s %6s  %-38s %s\n" "$grp" "$a" "$e" "${safe}.txt" "$note" >> "$idx"
    done < "$hdir/.ns.all"

    rm -f "$hdir/.ns.derived" "$hdir/.ns.declared" "$hdir/.ns.all"
    echo "[repolist] $hdir/: $(ls "$hdir" | grep -c '\.txt$') files (incl. _GROUPS.txt index)" >&2
  done
fi
