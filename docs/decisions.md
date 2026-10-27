# Design decisions

Each entry records a decision, why it was made, and the alternatives that were not taken. Goals and principles are in [design.md](design.md); the history of changes is in the [CHANGELOG](../CHANGELOG.md).

## Implementation

**Go standard library only, with the Go types as the data contract.** Few dependencies keep the CLI easy to audit. The [evidence types](../internal/evidence/evidence.go) are the only definition of the format; a separate JSON Schema was not added, to avoid two sources of truth.

**Skill kept in this repository as one canonical file.** [scripts/install-skill.sh](../scripts/install-skill.sh) links it into a project for Claude Code or Codex and refuses to overwrite an existing entry. Copying it per client was rejected because copies drift apart.

**MIT License.** The license covers the source code only; it does not relicense the data provided by external APIs.

## Sources

**CVE Program as the base record, NVD as supplementary.** NVD CPE configurations and CVSS metrics are kept in their original structure rather than flattened, so that no interpretation is introduced during collection.

**Only GitHub advisories referenced by the CVE are fetched as advisories.** Fetching arbitrary vendor HTML was rejected: it widens both the work of verifying sources and the SSRF attack surface. Unsupported reference URLs are kept with the reason they were not fetched, and keep their query and fragment so that they point to exactly what the source cited.

**A response is validated completely before any fact is taken from it.** This prevents partial facts from a source that later fails validation.

**Retrieved and usable are different states.** A response can be retrieved yet carry no evidence. A KEV catalog is used to decide absence only when its declared `count` is a non-negative integer that matches its entries. An NVD response must have an integral `totalResults` matching its records, and every record must have a description. A GitHub advisory must carry a `ghsa_id` that matches the reference. A RESERVED CVE record alone does not count as usable evidence, so the CLI exits with 1.

**The complete KEV catalog is used, and saved in full as a fixture.** A reduced fixture would misrepresent an incomplete catalog as complete, which is exactly the failure that absence decisions must avoid.

**GitHub advisory credits are not collected.** They identify individuals and are not needed to understand or remediate a vulnerability. Severity, CVSS, CWE, state and withdrawal are collected because they affect whether the advisory can be relied on.

## Evidence format

**Differing descriptions are conflict candidates, not conflicts.** Only descriptions in the same language are compared, so translations are not reported. Whether a difference in wording is a real contradiction is left to the Skill or a human. Semantic comparison of version ranges is not implemented.

**Schema 0.2: values are stored once, located by JSON Pointer.** `cvss`, `affected` and `fixed` became Fact ID indexes instead of copies of facts, and each fact records a `source_pointer` into the retrieved body, with `original` only when the value was normalized. Storing excerpt strings was rejected because it duplicates the source. No compatibility layer for 0.1 was written, as 0.1 was never released.

## Reports and diagrams

**Two diagrams with different purposes.** `overview.mmd` explains the entry point, root cause and impact in plain language; `diagram.mmd` traces the causal chain the sources describe. Combining both purposes in one diagram made it too technical for beginners and too vague for engineers.

**Diagram accuracy is enforced by rules and tests, not by the CLI.** The Skill requires a fact citation or an "unknown" mark on every node, and forbids joining paths with different preconditions. Tests check the sample's citations, safe syntax, and that proven and unproven impacts do not share a path. Validating user-generated reports with the CLI is planned (see [remaining work](design.md#remaining-work)).

## Project

**Funding through GitHub Sponsors only, with nothing gated behind it.** Every feature stays free, and sponsorship does not buy support, priorities or deadlines, so that the project needs no license checks, paid tiers or extra services to maintain. The Sponsor button and one short section in each README are the only places it is mentioned.
