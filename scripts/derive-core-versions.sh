#!/usr/bin/env bash
# derive-core-versions.sh <composer.json> [package]
# Prints the supported TYPO3 core MAJOR versions of a constraint, one per line (e.g. "13", "14").
#
# The majors are read from the extension's own `typo3/cms-core` constraint, because that is where
# supported core versions are declared. They are then used to pin a core for SBOM generation via
# `typo3/minimal:^<major>` — see sbom-generate.sh.
#
# Why majors and not major.minor: the pin is `typo3/minimal:^13`, which resolves to the newest
# release of that core major. Pinning `~13.4.34` would freeze the SBOM to one patch level and would
# have to be re-derived every time the extension bumps its constraint.
set -euo pipefail
FILE="${1:?usage: derive-core-versions.sh <composer.json> [package]}"
PKG="${2:-typo3/cms-core}"
jq -r --arg p "$PKG" '(.require[$p] // .["require-dev"][$p] // "")' "$FILE" \
  | tr '|,' '\n\n' \
  | grep -oE '[0-9]+\.[0-9]+' \
  | cut -d. -f1 \
  | sort -un
