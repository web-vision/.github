#!/usr/bin/env bash
# sbom-generate.sh — produce one or more CycloneDX BOMs for a single checked-out repository.
#
#   sbom-generate.sh --dir <path> --class <sbom_class> --name <component-name>
#                    --version <component-version> [--out <dir>] [--core-versions "13 14"]
#
# Emits: <out>/<slug>[.<variant>].cdx.json  (+ .sha256), and prints one TSV line per BOM:
#        <bomfile>\t<variant>
#
# Design notes (see ../docs/01-architecture.md):
#  * The CycloneDX composer plugin is installed into an ISOLATED COMPOSER_HOME. It therefore does
#    NOT inherit the target project's platform, and reads even Composer-1 locks on modern PHP.
#  * For lock-bearing repos nothing is resolved: no credentials, no network, no PHP matrix.
#  * Spec version is pinned to 1.6 — Dependency-Track 5.0.4 / 4.14.3 reject 1.7.
set -euo pipefail

SBOM_TOOL_VERSION="${SBOM_TOOL_VERSION:-6.2.0}"
SPEC_VERSION="${SPEC_VERSION:-1.6}"
export COMPOSER_HOME="${COMPOSER_HOME:-/tmp/composer-sbom}"
export COMPOSER_ALLOW_SUPERUSER=1

DIR=""; CLASS=""; NAME=""; VERSION=""; OUT="sbom-output"; CORE_VERSIONS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2;;
    --class) CLASS="$2"; shift 2;;
    --name) NAME="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --core-versions) CORE_VERSIONS="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$DIR" ] && [ -n "$CLASS" ] && [ -n "$NAME" ] || { echo "usage: see header" >&2; exit 2; }
mkdir -p "$OUT"
# Resolve to absolute paths: several classes cd into a working copy, which would break
# relative output paths and relative --dir values.
OUT="$(cd "$OUT" && pwd)"
DIR="$(cd "$DIR" && pwd)"
SLUG="$(printf '%s' "$NAME" | tr '/' '-' | tr -cd 'A-Za-z0-9._-')"

log() { printf '[sbom] %s\n' "$*" >&2; }


# prepare_resolve <dir> — settings shared by every resolving class.
prepare_resolve() {
  ( cd "$1"
    composer config lock true
    # Composer refuses to resolve a version affected by a security advisory. For an SBOM that is
    # backwards: the whole point is to record what an extension actually installs, INCLUDING the
    # vulnerable versions, so Dependency-Track can flag them. Blocking resolution makes the tool
    # blind exactly where it matters - an extension targeting an end-of-life core cannot be
    # inventoried at all, which is the case most worth knowing about.
    # Measured: fgtclb/content-notes (TYPO3 ^11.5) fails outright with 44 advisory-blocked
    # candidates, and resolves to 80 packages with this set - composer then reporting 27 advisories
    # affecting 6 packages, which is the finding we want recorded rather than suppressed.
    composer config policy.advisories.block false 2>/dev/null || true

    # Drop require-dev before resolving. The BOM is emitted with --omit=dev, so development
    # dependencies never reach the output - resolving them can only fail the run. And it does:
    # typo3/minimal pulls in typo3/cms-install, which requires nikic/php-parser ^4, while a modern
    # require-dev commonly pins ^5. web-vision/typo3-enable-translated-content fails on exactly that
    # conflict and resolves cleanly once require-dev is out of the way.
    if [ -f composer.json ] && jq -e 'has("require-dev")' composer.json >/dev/null 2>&1; then
      jq 'del(."require-dev")' composer.json > composer.json.sbom && mv composer.json.sbom composer.json
    fi
  ) >&2
}

ensure_plugin() {
  [ -x "$COMPOSER_HOME/vendor/bin/.nothing" ] 2>/dev/null || true
  if ! composer global show cyclonedx/cyclonedx-php-composer >/dev/null 2>&1; then
    log "installing cyclonedx-php-composer:${SBOM_TOOL_VERSION} into ${COMPOSER_HOME}"
    composer global config --no-interaction allow-plugins.cyclonedx/cyclonedx-php-composer true
    composer global require --no-interaction --no-progress --prefer-dist \
      "cyclonedx/cyclonedx-php-composer:${SBOM_TOOL_VERSION}" >&2
  fi
}

# make_bom <working-dir> <output-file> <component-version>
make_bom() {
  local wd="$1" outfile="$2" mcver="$3"
  ( cd "$wd" && composer CycloneDX:make-sbom \
      --output-format=JSON \
      --output-file="$outfile" \
      --spec-version="$SPEC_VERSION" \
      --output-reproducible \
      --validate \
      --omit=dev \
      ${mcver:+--mc-version="$mcver"} \
      composer.json ) >&2
}

emit() { # emit <file> <variant>
  sha256sum "$1" > "$1.sha256"
  printf '%s\t%s\n' "$1" "$2"
}

case "$CLASS" in

  composer-lock|composer-lock+magento-appcode)
    # Lock present: read it directly. No resolve, no credentials, no network.
    ensure_plugin
    OUTFILE="$OUT/${SLUG}.cdx.json"
    make_bom "$DIR" "$OUTFILE" "$VERSION"
    if [ "$CLASS" = "composer-lock+magento-appcode" ]; then
      # Magento 2 shops copy-install modules into app/code that never appear in composer.lock.
      # Merge them in as first-class components, or the SBOM understates third-party code -
      # measured at 7-12 vendors per shop, which is exactly the commercial code the CRA targets.
      helper="$(dirname "$0")/magento-appcode-merge.php"
      if [ -f "$helper" ]; then
        log "harvesting app/code modules not present in composer.lock"
        php "$helper" "$DIR" "$OUTFILE"
      else
        # Degrade loudly rather than dying: the lock-based BOM is still valid and useful, it just
        # under-reports app/code. Silence here would let an incomplete SBOM look complete.
        log "WARNING: $(basename "$helper") not implemented - emitting the lock-only BOM."
        log "WARNING: copy-installed app/code modules (7-12 vendors per shop) are NOT included."
      fi
    fi
    emit "$OUTFILE" "default"
    ;;

  composer-corelocks)
    # Monorepo / extension that commits one lock per supported core (core-13/, core14/, ...).
    ensure_plugin
    found=0
    for lockdir in "$DIR"/core-* "$DIR"/core*; do
      [ -f "$lockdir/composer.lock" ] || continue
      variant="$(basename "$lockdir")"
      OUTFILE="$OUT/${SLUG}.${variant}.cdx.json"
      make_bom "$lockdir" "$OUTFILE" "$VERSION"
      emit "$OUTFILE" "$variant"
      found=1
    done
    [ "$found" = 1 ] || { log "ERROR: class composer-corelocks but no core-*/composer.lock found"; exit 1; }
    ;;

  composer-resolve-matrix)
    # Dual/multi-core extension with no lock: resolve once per supported core major.
    # A single resolve would silently pick one branch of "^12.4 || ^13.4" and misreport the rest.
    #
    # The core is pinned with `typo3/minimal:^<major>` added as a DEV requirement, not by narrowing
    # `typo3/cms-core`. Two reasons:
    #  * `composer update --with typo3/cms-core:~13.4.0` is rejected unless the temporary constraint
    #    is a SUBSET of the declared one, so it fails on any extension that does not declare exactly
    #    that range ("The temporary constraint ... must be a subset of the constraint in your
    #    composer.json"). Adding a requirement has no such restriction.
    #  * `typo3/minimal` is the metapackage that actually defines a coherent minimal core install, so
    #    `^13` resolves the whole typo3/cms-* set consistently rather than pinning one package.
    # It is added as --dev so that `--omit=dev` keeps the test harness out of the SBOM, while
    # `typo3/cms-core` — a real runtime requirement of the extension — stays in the component list at
    # the version that core major resolved to.
    ensure_plugin
    if [ -z "$CORE_VERSIONS" ]; then
      CORE_VERSIONS="$("$(dirname "$0")/derive-core-versions.sh" "$DIR/composer.json" | tr '\n' ' ')"
      log "derived core majors from composer.json: ${CORE_VERSIONS:-<none>}"
    fi
    [ -n "${CORE_VERSIONS// /}" ] || { log "ERROR: no typo3/cms-core majors derivable for $NAME"; exit 2; }
    for major in $CORE_VERSIONS; do
      major="${major%%.*}"                      # tolerate "13.4" being passed in explicitly
      work="$(mktemp -d)"; cp -a "$DIR/." "$work/"
      prepare_resolve "$work"
      ( cd "$work"
        composer require --dev "typo3/minimal:^${major}" --no-update --no-interaction
        # -W lets transitive deps move; --no-install keeps it fast and vendor-free.
        # composer:2 images lack ext-intl, so platform reqs must be ignored.
        composer update --no-interaction --no-progress --no-install -W --ignore-platform-reqs ) >&2
      OUTFILE="$OUT/${SLUG}.typo3-${major}.cdx.json"
      make_bom "$work" "$OUTFILE" "$VERSION"
      emit "$OUTFILE" "typo3-${major}"
      rm -rf "$work"
    done
    ;;

  composer-resolve)
    # Single-target package with no lock: one resolve.
    ensure_plugin
    work="$(mktemp -d)"; cp -a "$DIR/." "$work/"
    prepare_resolve "$work"
    ( cd "$work"
      composer update --no-interaction --no-progress --no-install -W --ignore-platform-reqs ) >&2
    OUTFILE="$OUT/${SLUG}.cdx.json"
    make_bom "$work" "$OUTFILE" "$VERSION"
    emit "$OUTFILE" "default"
    rm -rf "$work"
    ;;

  vendor-installed-php)
    # Production docroot with a committed vendor/ but no composer.json/lock
    # (e.g. WHMCS). Neither syft nor trivy catalogues vendor/composer/installed.php.
    OUTFILE="$OUT/${SLUG}.cdx.json"
    helper="$(dirname "$0")/installed-php-to-bom.php"
    [ -f "$helper" ] || { log "ERROR: $(basename "$helper") is not implemented; class vendor-installed-php cannot be generated"; exit 3; }
    php "$helper" "$DIR" "$NAME" "$VERSION" > "$OUTFILE"
    emit "$OUTFILE" "default"
    ;;

  magento1-harvest)
    # Magento 1 tree: no composer metadata at all. syft/trivy/cdxgen all return 0 components.
    OUTFILE="$OUT/${SLUG}.cdx.json"
    php "$(dirname "$0")/magento1-sbom.php" --dir "$DIR" --name "$NAME" \
        --version "${VERSION:-0.0.0}" > "$OUTFILE"
    emit "$OUTFILE" "default"
    ;;

  container-image)
    # The artefact that matters is the built image, not the repo.
    : "${IMAGE_REF:?IMAGE_REF must be set for class container-image}"
    OUTFILE="$OUT/${SLUG}.cdx.json"
    syft "$IMAGE_REF" -o "cyclonedx-json@${SPEC_VERSION}" > "$OUTFILE"
    emit "$OUTFILE" "image"
    ;;

  npm)
    OUTFILE="$OUT/${SLUG}.cdx.json"
    ( cd "$DIR" && cyclonedx-npm --omit dev --spec-version "$SPEC_VERSION" \
        --output-format JSON --output-file "$OUTFILE" ) >&2
    emit "$OUTFILE" "default"
    ;;

  none)
    log "class 'none' — nothing to generate for $NAME"; exit 0 ;;

  *) log "ERROR: unknown class '$CLASS'"; exit 2 ;;
esac
