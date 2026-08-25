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
# Fall back to any other typo3/cms-* requirement when typo3/cms-core is absent. Extensions commonly
# declare only the subsystems they use - fgtclb/newspage requires cms-extbase, cms-fluid and
# cms-frontend but never cms-core - and reading only cms-core yields no majors for those, so a
# multi-core extension would be resolved once and silently described against one core.
jq -r --arg p "$PKG" '
  (.require[$p] // .["require-dev"][$p] // "") as $direct
  | if $direct != "" then $direct
    else [ (.require // {}) + (.["require-dev"] // {})
           | to_entries[]
           | select(.key | startswith("typo3/cms-"))
           | .value ] | join(" || ")
    end' "$FILE" \
  | tr '|,' '\n\n' \
  | grep -oE '[0-9]+\.[0-9]+' \
  | cut -d. -f1 \
  | sort -un
