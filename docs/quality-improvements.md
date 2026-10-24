# 0.1.0-dev.1 quality improvements

On 2026-10-24, the initial implementation from [PR #1](https://github.com/hidetzu/vulnograph/pull/1) was reviewed for data accuracy, traceability of evidence, and clarity of reports. This page records the findings and the improvement items R1–R7, numbered in implementation order and implemented in [PR #2](https://github.com/hidetzu/vulnograph/pull/2). Accuracy and explanation quality took priority over new features, and the architecture was kept. The reasons for the resulting design are in [decisions.md](decisions.md).

## Findings

- Some paths did not distinguish a failed fetch from a fetch that returned nothing usable. KEV `count` was not validated, and an NVD record containing only an ID was `ok` and could justify exit code 0.
- Every fact's `evidence_excerpt` was the fixed text `Structured source field: <field>`, which did not show where in the source the value came from.
- `cvss`, `affected` and `fixed` were full copies of facts and made up most of the golden file.
- GitHub advisory CVSS, CWE, severity and withdrawal were not collected, so a withdrawn advisory could be used as valid evidence.
- The only diagram described the technical causal chain; there was no diagram that let beginners see the entry point, cause and impact.

## Priority 1: data accuracy

**R1. Validate the KEV catalog count against its entries.** A missing or mismatched `count`, or an entry without a `cveID`, makes the source `fetch_failed` and the KEV signal `unknown`. A duplicate listing produces a warning.

**R2. Treat NVD responses without usable content as failures.** A `totalResults` that does not match the records, or a record without a description, is `fetch_failed` and adds no facts. Empty status, metrics and configurations are not recorded. Exit code 1 when neither the CVE record nor NVD provides usable evidence.

**R3. Reproduce malformed input with fixtures.** Each case under `testdata/anomalies` overrides responses of the synthetic fixture, and a table-driven test checks the expected statuses and signals. See [testdata/README.md](../testdata/README.md).

## Priority 2: traceability

**R4. Record each fact's location in its source (schema 0.2).** `evidence_excerpt` was replaced by `source_pointer`, a JSON Pointer into the retrieved body, and `original` for normalized values.

**R5. Remove the duplication of facts (schema 0.2).** `cvss`, `affected` and `fixed` became arrays of Fact IDs.

**R6. Collect the missing GitHub advisory information.** The advisory ID is checked against the reference; severity, CVSS, CWE, state and withdrawal are recorded; withdrawn or unpublished advisories produce warnings; identical patched versions are recorded once.

## Priority 3: report clarity

**R7. Add a beginner-friendly overview diagram.** The Skill writes `overview.mmd` (entry point, root cause, impact in plain language) in addition to the technical `diagram.mmd`. Every node cites a fact or is marked unknown, and tests check the sample's diagrams.

Review of PR #2 led to further fixes before it was merged: requiring a well-formed advisory ID, accepting only integral counts, and separating the startup and post-startup attack paths in the sample diagrams.

Work not covered here is listed under [remaining work](design.md#remaining-work).
