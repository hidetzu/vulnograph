# Changelog

All notable changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/); 0.1.0-dev.x releases may include incompatible changes.

## [0.1.0-dev.2](https://github.com/hidetzu/vulnograph/releases/tag/v0.1.0-dev.2) - 2026-10-29

### CLI

- Evidence format 0.3. The `affected` index now also points at facts whose `status` says a product is not affected, under investigation or merely recommended (from CSAF product statuses), and `fixed` facts from CSAF carry a product ID, name and branch path instead of a plain version. Readers that took every entry of `affected` as affected, or every `fixed` value as a version string, must read `status` and the value shape; nothing else changed in the layout.
- `fixed` facts are now also derived from the CVE record's version ranges: a version listed as unaffected, a `changes` entry to unaffected, and the `lessThan` of an affected range when the product's `defaultStatus` is `unaffected`. Each fact carries the vendor, product, branch and a `source_pointer` into the record. Bounds the record does not declare unaffected, `lessThanOrEqual`, wildcards and NVD CPE ranges are not read as fixes. In the CVE-2026-109618 baseline the record's four branches now appear as F4–F7 next to the GHSA values, so later fact IDs in the sample and golden evidence moved by four.
- A new `affected_bound` fact records the `lessThan` of an affected range that the record does not declare unaffected (`defaultStatus` absent or `unknown`, as in Microsoft records). It has the shape of a `fixed` fact but is not indexed as one; the Skill presents it as an estimate, not a fix.
- Cisco Security Advisories referenced by the CVE are now fetched in CSAF 2.0 form from Cisco's distribution on `www.cisco.com`, which joins the host allowlist. The advisory ID in the reference is looked up in Cisco's CSAF index (recorded as a `csaf_index` source) and the listed document is retrieved as a `csaf` source; the advisory web page is never fetched. The document must carry the referenced tracking ID and list the CVE before any fact is taken, and only its entries for the CVE are read. Recorded: tracking status as `advisory_state` (`final` is published; others warn), the title, summary notes as `advisory_description`, every other note except the legal disclaimer as the new `advisory_note` fact (Cisco states fixed releases and workarounds there), CWE, CVSS, each product status with the product's name and branch path as `affected` (with its `status`) or `fixed`, and the new `remediation` and `threat` facts. A product ID the product tree does not define is kept with a warning, as is a product ID listed under contradicting statuses. `recommended` is kept as a status of its own and never read as fixed.
- The `User-Agent` now includes the project URL, `vulnograph/<version> (+https://github.com/hidetzu/vulnograph)`, because Cisco's CDN refuses a bare product token.

### Skill

- `fixed` is written as confirmed and `affected_bound` as an estimate with its premise; the two are never mixed in one column.
- CSAF sources: only `known_affected` is written as affected, `known_not_affected` as the vendor's negative statement, and a fixed release taken from a Fixed Software note cites that note and says it is not a structured value.

### Documentation and project

- A validation plan for reviewing reports on 10–20 CVEs before 0.1.0.
- A "Usage feedback" issue template for reporting whether a report helped with a real decision.
- A Sponsor button and a short Support section in the README. Sponsorship does not come with support or feature commitments.

## [0.1.0-dev.1](https://github.com/hidetzu/vulnograph/releases/tag/v0.1.0-dev.1) - 2026-10-24

First development release.

### CLI

- `vulnograph fetch` collects a CVE from the CVE Program, NVD, GitHub Security Advisories referenced by the CVE, the CISA KEV catalog and FIRST EPSS, and writes source-attributed evidence as JSON.
- Evidence format 0.2: each fact records its source and a JSON Pointer (`source_pointer`) to its location in the retrieved body, with `original` for normalized values. `cvss`, `affected` and `fixed` are Fact ID indexes. Format 0.1 existed only during development and is not supported.
- Each source is reported as `ok`, `not_found`, `unknown`, `fetch_failed` or `not_applicable`. A response is validated completely before any fact is taken from it, and a failed or incomplete response is never reported as absent:
  - the KEV catalog is used to decide absence only when its `count` is a non-negative integer that matches its entries and every entry has a `cveID`; duplicate listings produce a warning,
  - an NVD response must have an integral `totalResults` matching its records, and every record must have a description,
  - a GitHub advisory must have a `ghsa_id` matching the reference; its severity, CVSS, CWE, state and withdrawal are recorded, and withdrawn or unpublished advisories produce warnings.
- Description differences between sources in the same language are reported as conflict candidates and never merged.
- Exit code 0 when a published CVE record or an NVD record with content is available, 1 when there is no usable record (including a RESERVED record alone), the CVE is rejected, or output fails, and 2 for invalid arguments.
- Network access is limited to a fixed HTTPS host allowlist with public-IP validation, no redirects or proxies, size and time limits, per-host rate limiting, and bounded retries. Reference URLs keep their query and fragment.
- `--output` creates new files with mode 0644 and keeps the permissions of an existing file.

### Skill

- A single Agent Skill for Claude Code and Codex, installed with `scripts/install-skill.sh`, writes a Japanese `report.md`, a beginner-friendly `overview.mmd` (entry point, root cause, impact) and a technical `diagram.mmd`.
- Every report claim and diagram node cites a fact and its source; unsupported entry points and paths are marked unknown. Paths with different preconditions are not joined.
- The Skill stops without writing evidence when the CLI is not on `PATH`.

### Samples, tests and documentation

- Saved API snapshots and a sample report for CVE-2026-109618.
- Offline tests with golden output, malformed-input fixtures under `testdata/anomalies`, traceability checks of every fact, and checks of the sample diagrams' citations and safety.
- README in English and Japanese, evidence format and network safety documentation, design notes, contribution and security policies, and attribution of third-party data in `NOTICE`.
