# Validation plan

This page describes how report quality is reviewed for the [0.1.0 definition of done](design.md#010-definition-of-done): 10–20 CVEs of different types, with no unsupported claims, wrong fixed versions, or mitigations described as complete fixes, and every error turned into a test case. So far only CVE-2026-109618 has been reviewed.

## Selecting CVEs

Choose CVEs that differ in vulnerability type and in the shape of the evidence, since most errors come from evidence that is missing, partial or conflicting rather than from the vulnerability type itself. The candidates below are a starting point; replace any that do not exercise the intended case.

| Case | Candidate |
| --- | --- |
| RCE, KEV listed, GHSA available | CVE-2021-44228 (Log4j) |
| RCE in a web framework | CVE-2022-22965 (Spring Framework) |
| SQL injection, KEV listed, vendor advisory only | CVE-2023-34362 (MOVEit Transfer) |
| XSS in a library, GHSA with patched versions | CVE-2020-11022 (jQuery) |
| DoS in a protocol, many affected products | CVE-2023-44487 (HTTP/2 Rapid Reset) |
| Path traversal | CVE-2021-41773 (Apache HTTP Server) |
| Memory corruption in a library used by many products | CVE-2023-4863 (libwebp) |
| Local privilege escalation | CVE-2021-3156 (sudo) |
| Linux kernel, fixes backported by distributions | CVE-2022-0847 |
| Information disclosure | CVE-2014-0160 (OpenSSL) |
| Supply-chain compromise | CVE-2024-3094 (xz) |
| Authentication bypass | CVE-2024-27198 (TeamCity) |
| Recently published, NVD analysis not yet available | Pick at review time |
| Rejected or reserved CVE | Pick at review time; the CLI should exit with 1 |

## Reviewing a report

For each CVE, generate the report with the released CLI and Skill, then check it against the cited sources:

1. Every claim and diagram node cites a fact that exists, and the fact says what the claim says.
2. Affected and fixed versions match the sources, including their ranges and the products they apply to.
3. No attack condition, path or impact appears that the sources do not state; unproven impacts are not presented as demonstrated.
4. Workarounds and mitigations are not described as complete fixes.
5. Gaps, failed sources and conflicts in the evidence are reported, not filled in.
6. KEV, EPSS and CVSS are reported as separate signals, and absence from KEV is not read as "not exploited".
7. Both diagrams render, and paths with different preconditions are not joined.

Record the result of each CVE in one issue, using the "Data accuracy" template for each error found, so that the review history stays in GitHub.

## Turning errors into tests

- An error in the evidence becomes a fixture under `testdata/anomalies`, or a new saved snapshot if the upstream data is real and needed in full.
- An error in a report becomes a change to [SKILL.md](../skills/vulnograph/SKILL.md). If the report is kept as a sample under `examples`, its citations are checked by `go test ./examples`.
- A CVE whose report needed no change is listed in the review issue; it does not need a fixture.

## Time to understanding

Measuring time saved is not required for 0.1.0. During the review, note how long the report takes to check against the sources, and ask users to report time compared with reading the sources themselves in [usage feedback](https://github.com/hidetzu/vulnograph/issues/new?template=feedback.yml). These are rough, self-reported numbers and are not published as a claim.
