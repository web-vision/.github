# Security Policy

web-vision GmbH (including our Extendware products) develops and
maintains a portfolio of TYPO3 and Magento extensions, and apps. As a manufacturer of products with digital elements
under the EU Cyber Resilience Act (Regulation (EU) 2024/2847), we are
committed to identifying, assessing, and remediating security
vulnerabilities across our products in a timely manner, and to
coordinating responsibly with security researchers.

This is our general, company-wide policy. Individual repositories may
publish their own `SECURITY.md` with product-specific details (supported
versions, scope, end of support date); where one exists, it takes
precedence for that product. This policy applies to any web-vision /
Extendware repository that does not have its own.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately — **do not**
open a public GitHub/GitLab issue.

- **Report here:** https://security.web-vision.de (our secure incident report form) or via email security@web-vision.de
- **Please include:** the affected product and version(s), a description
  of the issue, steps to reproduce or a proof of concept, and the
  potential impact.

### What to expect

| Step                         | Timeframe                         |
| ----------------------------- | ---------------------------------- |
| Acknowledgement of your report | within 1 business day (typically much faster) |
| Status updates                | at least every 7 days until resolved |
| Fix / mitigation, based on severity | Critical/High: as fast as possible; Medium/Low: next scheduled release |

We coordinate the disclosure timeline with the reporter and aim for a
resolution before any public disclosure. If you'd like credit for your
finding, let us know how you'd like to be named; we're also happy to keep
your report confidential if you prefer.

<!--
  Deliberately no fixed "triage within X hours" commitment here: it
  would collide with two other, independent deadlines defined in the
  CRA roadmap — the internal 4h response time of the Vulnerability
  Coordinator (Phase 0, No. 2) and the statutory 24h/72h/14-day
  notification deadline to ENISA for actively exploited vulnerabilities
  (Art. 14 CRA, Phase 0, No. 5).
-->

## Safe Harbor

We consider security research conducted in good faith, in accordance
with this policy, to be authorized. We will not pursue legal action
against researchers who:

- make a genuine effort to avoid privacy violations, data destruction,
  and service interruption during their research,
- report a vulnerability promptly and do not exploit it beyond what is
  necessary to demonstrate the issue,
- do not publicly disclose the vulnerability before we have had a
  reasonable opportunity to address it (see timeframes above).

## Scope

In scope: the source code, released versions, and official distribution
channels of web-vision GmbH and Extendware products (e.g. TYPO3
Extension Repository, Packagist, Magento Marketplace) — as far as they
are not covered by a more specific product-level `SECURITY.md`.

Out of scope: third-party dependencies (please report those upstream,
but feel free to let us know so we can track and update them), the host
applications (TYPO3 / Magento core) themselves unless directly caused by
our code, and any product explicitly marked end-of-life (see the
product's own documentation).

## Support Period

Unless a product's own documentation states otherwise, our target
support period is at least 5 years from initial release. The specific
end-of-support date for a given product is communicated in that
product's listing/description and, where applicable, its own
`SECURITY.md`.

## Coordinator

Vulnerability reports across our product portfolio are handled by the
Vulnerability Coordinator team at web-vision GmbH, under the oversight
of our GRC/CISO function.
