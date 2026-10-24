# Changelog

All notable changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/); 0.1.0-dev.x releases may include incompatible changes.

## Unreleased

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
