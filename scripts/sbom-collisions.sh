#!/usr/bin/env bash
# sbom-collisions.sh — find repositories that would collide in Dependency-Track, or that duplicate
# each other across hosts, so the estate can be pruned before onboarding rather than after.
#
#   sbom-collisions.sh --in classified.jsonl [--tsv out.tsv] [--md out.md]
#
# Two very different things get called "duplicates", and conflating them wastes review time:
#
#   PACKAGE collisions   Two or more repositories publish the SAME composer package name, and under
#                        the naming rules a distributable package is keyed in Dependency-Track by
#                        that name. They WILL land in one DT project and overwrite each other's
#                        component set on every run. These need a decision before onboarding.
#
#   APPLICATION overlaps Many repositories legitimately share a distribution metapackage name
#                        (magento/project-community-edition, typo3/cms-base-distribution). Under the
#                        naming rules applications are keyed by <host>/<namespace>/<repo>, so these
#                        do NOT collide. Listed separately, for information only.
#
# A repository is treated as a distributable package when its composer type is an extension,
# library, module, plugin or theme; everything else is an application.
#
# THIRD CATEGORY, and the one that actually bites: a shop docroot whose root composer.json belongs to
# a VENDORED MODULE, not to the shop. Four ztv shops each ship phoenix/navconnect's manifest at the
# docroot root, so a naive reading calls them all one package. Keying those by composer name would
# merge four unrelated customer shops into a single Dependency-Track project - worse than a
# duplicate, because the components of one shop would silently replace another's. These are detected
# from the docroot signature and reported separately: the fix is to key them by path, not to pick a
# winner.
set -euo pipefail
IN=""; TSV=""; MD=""
while [ $# -gt 0 ]; do
  case "$1" in
    --in) IN="$2"; shift 2;; --tsv) TSV="$2"; shift 2;; --md) MD="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$IN" ] || { echo "--in <classified.jsonl> required" >&2; exit 2; }

PKG_TYPES='["typo3-cms-extension","library","magento2-module","magento2-component","magento2-theme","magento-module","magento-extension","composer-plugin","phpcodesniffer-standard","phpstan-extension","symfony-bundle","metapackage"]'

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# An application docroot carrying a package manifest: Magento 1 layout (app + lib + one of
# skin/pkginfo/var/downloader) or a committed vendor/ tree at the root.
APPTREE='(([.root_files[]?] | index("app")) != null
          and (([.root_files[]?] | index("lib")) != null)
          and ((([.root_files[]?] | index("skin")) != null)
            or (([.root_files[]?] | index("pkginfo")) != null)
            or (([.root_files[]?] | index("magentodownloader")) != null)
            or (([.root_files[]?] | index("downloader")) != null)))'

# --- package-name collisions: the ones that actually break Dependency-Track -------------------
jq -r --argjson pt "$PKG_TYPES" --arg apptree "$APPTREE" '
  select((.composer_name // "") != "")
  | (.composer_type // "") as $ct | select(($pt | index($ct)) != null)
  | [.composer_name, .host, .path, (.last_commit // ""), (.sbom_excluded|tostring),
     (.sbom_exclude_reason // ""), (.visibility // "")] | @tsv' "$IN" \
  | sort > "$TMP/pkgs.all.tsv"

# split off the docroot-with-a-module-manifest cases
jq -r --argjson pt "$PKG_TYPES" "
  select((.composer_name // \"\") != \"\")
  | (.composer_type // \"\") as \$ct | select((\$pt | index(\$ct)) != null)
  | select($APPTREE)
  | [.composer_name, .host, .path, (.last_commit // \"\")] | @tsv" "$IN" | sort > "$TMP/apptree.tsv"
cut -f3 "$TMP/apptree.tsv" | sort -u > "$TMP/apptree-paths.txt"
awk -F'\t' 'NR==FNR{skip[$1]=1; next} !($3 in skip)' "$TMP/apptree-paths.txt" "$TMP/pkgs.all.tsv" > "$TMP/pkgs.tsv"
awk -F'\t' '{c[$1]++} END{for(k in c) if(c[k]>1) print k}' "$TMP/pkgs.tsv" | sort > "$TMP/dupnames.txt"

# --- application overlaps: shared distribution metapackages, harmless under path naming -------
jq -r --argjson pt "$PKG_TYPES" '
  select((.composer_name // "") != "")
  | (.composer_type // "") as $ct | select(($pt | index($ct)) == null)
  | [.composer_name, .host, .path] | @tsv' "$IN" | sort > "$TMP/apps.tsv"
awk -F'\t' '{c[$1]++} END{for(k in c) if(c[k]>1) print k"\t"c[k]}' "$TMP/apps.tsv" | sort > "$TMP/appdups.tsv"

# --- same repository basename on more than one host: possible mirrors -------------------------
jq -r '[(.path|split("/")|last), .host, .path, (.last_commit // "")] | @tsv' "$IN" | sort > "$TMP/base.tsv"
awk -F'\t' '{k=$1; h[k]=h[k]" "$2; c[k]++} END{for(k in c) if(c[k]>1){n=split(h[k],a," "); u=""; for(i=1;i<=n;i++){if(index(u,a[i])==0) u=u" "a[i]} ; split(u,b," "); if(length(b)>1) print k}}' "$TMP/base.tsv" | sort > "$TMP/basedups.txt"

# --- emit TSV ---------------------------------------------------------------------------------
if [ -n "$TSV" ]; then
  { printf 'kind\tkey\thost\tpath\tlast_commit\texcluded\texclude_reason\tvisibility\n'
    while IFS= read -r name; do
      [ -z "$name" ] && continue
      awk -F'\t' -v n="$name" '$1==n {printf "package-collision\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",$1,$2,$3,$4,$5,$6,$7}' "$TMP/pkgs.tsv"
    done < "$TMP/dupnames.txt"
    while IFS=$'\t' read -r name cnt; do
      [ -z "$name" ] && continue
      awk -F'\t' -v n="$name" '$1==n {printf "application-overlap\t%s\t%s\t%s\t\t\t\t\n",$1,$2,$3}' "$TMP/apps.tsv"
    done < "$TMP/appdups.tsv"
    while IFS= read -r base; do
      [ -z "$base" ] && continue
      awk -F'\t' -v b="$base" '$1==b {printf "basename-across-hosts\t%s\t%s\t%s\t%s\t\t\t\n",$1,$2,$3,$4}' "$TMP/base.tsv"
    done < "$TMP/basedups.txt"
  } > "$TSV"
  echo "[collisions] wrote $TSV" >&2
fi

# --- emit markdown ----------------------------------------------------------------------------
if [ -n "$MD" ]; then
  {
    echo "# Duplicates and collisions"
    echo
    echo "Generated by \`proposal/scripts/sbom-collisions.sh\` from the repository inventory."
    echo "Decide each **package collision** before onboarding: two repositories publishing one"
    echo "package name land in a single Dependency-Track project and overwrite each other on every"
    echo "run, so the portfolio silently shows whichever ran last."
    echo
    echo "For each group pick one: **keep** (authoritative), **archive**, or **exclude** (tag"
    echo "\`no-sbom\`). The \`sbom\` topic is what onboards a repository, so an untagged duplicate is"
    echo "already inert — but leaving it untagged is an implicit decision, not a recorded one."
    echo
    echo "## Package collisions — must be resolved"
    echo
    n=0
    while IFS= read -r name; do
      [ -z "$name" ] && continue
      n=$((n+1))
      echo "### \`$name\`"
      echo
      # Emit padded columns: the report is read as plain text at least as often as rendered.
      awk -F'\t' -v n="$name" 'BEGIN{
          h[1]="host"; h[2]="path"; h[3]="last commit"; h[4]="visibility"; h[5]="currently"
          for(i=1;i<=5;i++) w[i]=length(h[i])
        }
        $1==n {
          st = ($5=="true") ? "excluded: " $6 : "in scope"
          r++; c[r,1]=$2; c[r,2]="`" $3 "`"; c[r,3]=substr($4,1,10); c[r,4]=$7; c[r,5]=st
          for(i=1;i<=5;i++) if(length(c[r,i])>w[i]) w[i]=length(c[r,i])
        }
        END{
          line="|"; sep="|"
          for(i=1;i<=5;i++){ line=line sprintf(" %-*s |", w[i], h[i]); sep=sep sprintf("-%s-|", substr("--------------------------------------------------------------",1,w[i])) }
          print line; print sep
          for(j=1;j<=r;j++){ out="|"; for(i=1;i<=5;i++) out=out sprintf(" %-*s |", w[i], c[j,i]); print out }
        }' "$TMP/pkgs.tsv"
      echo
      echo "- [ ] keep: \`________\`  → tag \`sbom\`"
      echo "- [ ] archive / exclude the others → tag \`no-sbom\`"
      echo
    done < "$TMP/dupnames.txt"
    [ "$n" = 0 ] && echo "_None._" && echo
    echo "## Docroots carrying a vendored module's manifest — fix the naming, do not pick a winner"
    echo
    echo "These are **applications**, not packages: the repository is a shop docroot and the"
    echo "\`composer.json\` at its root belongs to a module vendored inside it. Keying them by composer"
    echo "name would merge unrelated customer shops into one Dependency-Track project, so they must be"
    echo "keyed by \`<host>/<namespace>/<repo>\` like any other application. No repository needs to be"
    echo "removed."
    echo
    if [ -s "$TMP/apptree.tsv" ]; then
      echo "| apparent composer name | host | path | last commit |"
      echo "|---|---|---|---|"
      awk -F'\t' '{printf "| `%s` | %s | `%s` | %s |\n", $1, $2, $3, substr($4,1,10)}' "$TMP/apptree.tsv"
    else
      echo "_None._"
    fi
    echo
    echo "## Application overlaps — informational"
    echo
    echo "These share a distribution metapackage name. Applications are keyed in Dependency-Track by"
    echo "\`<host>/<namespace>/<repo>\`, so they do **not** collide. No action needed."
    echo
    echo "| shared composer name | repositories |"
    echo "|---|---:|"
    while IFS=$'\t' read -r name cnt; do
      [ -z "$name" ] && continue
      printf '| `%s` | %s |\n' "$name" "$cnt"
    done < "$TMP/appdups.tsv"
    echo
    echo "## Same repository name on more than one host — possible mirrors"
    echo
    echo "Weaker signal than a package collision: a shared basename may be coincidence. Worth a look"
    echo "where the copies are both recent, which usually means a mirror that has started to diverge."
    echo
    echo "| name | host | path | last commit |"
    echo "|---|---|---|---|"
    while IFS= read -r base; do
      [ -z "$base" ] && continue
      awk -F'\t' -v b="$base" '$1==b {printf "| %s | %s | `%s` | %s |\n", $1, $2, $3, substr($4,1,10)}' "$TMP/base.tsv"
    done < "$TMP/basedups.txt"
  } > "$MD"
  echo "[collisions] wrote $MD" >&2
fi

echo "[collisions] package collisions: $(wc -l < "$TMP/dupnames.txt"), docroot-manifest cases: $(wc -l < "$TMP/apptree.tsv"), application overlaps: $(wc -l < "$TMP/appdups.tsv"), cross-host basenames: $(wc -l < "$TMP/basedups.txt")" >&2
