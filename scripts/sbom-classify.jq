# sbom-classify.jq — classification + exclusion rules for SBOM scope.
#
# Input : one repository object per line (see sbom-inventory.sh for the field contract).
# Output: the same object plus .sbom_class, .sbom_tier, .sbom_excluded, .sbom_exclude_reason
#
# Two fields cannot be derived from repository content and must come from the override file
# (scope-overrides.json): .commercial and .code_handover. They decide the CRA tier.

def has_root($n): (.root_files // []) | index($n) != null;

# ---------------------------------------------------------------- generation class
# Decides WHICH GENERATOR runs. Independent of whether the repo is in scope.
def sbom_class:
  if .has_lock then
    if (.magento_edition // "") != "" then "composer-lock+magento-appcode"
    else "composer-lock" end
  elif (.vendor_installed_php // false) then "vendor-installed-php"
  elif (.magento1_tree // false) then "magento1-harvest"
  elif (.composer_name // "") != "" then
    if (.core_locks // []) | length > 0 then "composer-corelocks"
    elif (.dual_core // false) then "composer-resolve-matrix"
    else "composer-resolve" end
  elif (.builds_image // false) then "container-image"
  elif (.has_package_json // false) then "npm"
  else "none" end;

# ---------------------------------------------------------------- exclusion rules
# R0 wins over everything; otherwise first match wins.
def exclude_reason:
  # Topic vocabulary (one word, one meaning):
  #   sbom               opt in. Gathered by the central sweep AND overrides every exclusion below.
  #   no-sbom            opt out. Never scanned, never expected in the coverage report.
  #   sbom-own-pipeline  carries its own sbom-job.yml; skipped by the sweep, still audited.
  if ((.topics // []) | index("sbom")) then null                              # R0 opt-in override
  elif ((.topics // []) | index("no-sbom")) then "R5 opt-out topic"
  elif (.archived // false) then "R1 archived"
  elif (.default_branch // "") == "" then "R2 empty default branch"
  elif (.is_mirror // false) then "R6 read-only import mirror"
  elif (.is_split_target // false) then "R7 monorepo split target (SBOM comes from the monorepo)"
  elif (.is_fork // false) then "R8 fork of a third-party upstream"
  elif (.personal_namespace // false) then "R4 personal namespace"
  elif (sbom_class == "none") then "R3 no dependency manifest of any kind"
  elif ((.duplicate_of // "") != "") then ("R9 duplicate of " + .duplicate_of)
  else null end;

# ---------------------------------------------------------------- CRA tier
# A = SBOM legally required (Annex I, from 2027-12-11)
# B = open-source steward (Art 24): policy/CVD/reporting; SBOM optional but cheap
# C = out of CRA scope (hosted service / NIS2) but operationally in scope
# D = excluded entirely
def sbom_tier:
  if (exclude_reason != null) then "D"
  elif (.commercial // false) then "A"
  elif (.code_handover // false) then "A"
  elif (.builds_image // false) and (.ships_to_customer // false) then "A"
  elif (.visibility // "") == "public" then "B"
  else "C" end;

# ---------------------------------------------------------------- cadence
# Dormancy is a CADENCE decision, not an exclusion. A dead repo whose code still runs in
# production still deserves one SBOM; it does not deserve a weekly pipeline.
#   weekly    - actively developed; regenerate on push to default branch + weekly
#   monthly   - still touched occasionally
#   snapshot  - generate once, then quarterly; never wire a per-repo pipeline into it
def sbom_cadence:
  (.last_commit // "") as $lc
  | if $lc == "" then "snapshot"
    elif $lc >= (.now_minus_6m  // "0000") then "weekly"
    elif $lc >= (.now_minus_24m // "0000") then "monthly"
    else "snapshot" end;

. + {
  sbom_class:          sbom_class,
  sbom_cadence:        sbom_cadence,
  sbom_exclude_reason: exclude_reason,
  sbom_excluded:       (exclude_reason != null),
  sbom_tier:           sbom_tier
}
