# purl-repair.jq — repair PURLs that Dependency-Track cannot correlate.
#
#   jq -f purl-repair.jq bom.json > bom.fixed.json
#
# Two problems this fixes, both measured in this estate:
#
# 1. Composer `dist.type: "path"` entries (14 of them in the fgtclb academic-extensions core locks)
#    are emitted without a usable PURL. They are real shipped packages and must be correlatable.
#
# 2. Any component whose PURL carries no `@version`. Dependency-Track reads the version from the
#    PURL (or a CPE) and NEVER from the CycloneDX `version` field: such a component is stored and
#    counted, but every analyzer drops it silently. It becomes invisible ballast that inflates
#    apparent coverage. Where the component has a `version` field we can rebuild the PURL; where it
#    does not, we tag it so the pre-upload assertion can refuse the document rather than let it pass.

def slug: gsub("[^A-Za-z0-9._~-]"; "-");

def repair_purl:
  . as $c
  | ($c.purl // "") as $p
  | ($c.version // "") as $v
  | if ($p != "" and ($p | test("@"))) then $c                     # already fine
    elif ($p != "" and $v != "") then
      $c + { purl: ($p + "@" + ($v | @uri)) }                      # append the known version
    elif ($v != "") then
      # No purl at all (path repositories, generic components): synthesise a composer purl from
      # group/name where possible, else a generic one. Always versioned.
      ( ($c.group // ($c.name | split("/")[0] // "")) ) as $g
      | ( ($c.name | split("/") | last) ) as $n
      | $c + { purl: ("pkg:composer/" + ($g|slug) + "/" + ($n|slug) + "@" + ($v|@uri)) }
    else
      $c + { "x-sbom-unanalysable": true }                         # cannot be repaired — flag it
    end;

.components = [ .components[]? | repair_purl ]
| .["x-sbom-unanalysable-count"] =
    ([ .components[]? | select(.["x-sbom-unanalysable"] == true) ] | length)
