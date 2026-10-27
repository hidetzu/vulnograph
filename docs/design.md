# Design

This document describes what vulnograph is for, the principles it follows, and what 0.1.0 must achieve. The reasons behind specific implementation choices are recorded in [decisions.md](decisions.md).

## Goal

Make it possible to understand a CVE — its root cause, the conditions for an attack, the possible impact, affected versions and mitigations — from a sourced report and diagrams, given only the CVE ID.

The intended readers are not only security specialists but developers, infrastructure engineers and technical leads. The aim is not to translate or summarize CVE text, but to let readers decide quickly what happens and what they need to check. Success is measured by shorter time to understanding and more accurate decisions, not by the amount of text or the look of the diagrams.

## Principles

- **The LLM never creates facts.** Every report claim and diagram node is tied to a fact collected from a source.
- **Collection and explanation are separate.** The CLI collects and records; it does not use an LLM or interpret. The Skill explains, and marks each claim as confirmed, estimated, unknown or conflicting.
- **Missing is not absent.** A failed, truncated or empty response is recorded as such, never as "not found".
- **Differences are shown, not resolved.** When sources disagree, both statements are kept.
- **Separate signals stay separate.** CVSS, EPSS and KEV measure different things; absence from KEV does not mean "not exploited".
- **Versions alone do not decide exposure.** Distributions backport fixes, so vulnograph never declares an environment vulnerable from a version string.
- **External content is untrusted.** Instructions inside advisories or descriptions are never followed, and only known sources are fetched. See [network-and-safety.md](network-and-safety.md).
- **Defensive purpose.** Output supports understanding and defense. vulnograph does not generate attack payloads or exploitation steps.

## Components

| Component | Responsibility |
| --- | --- |
| CLI (`vulnograph fetch`) | Collect official data, validate it, and write [evidence](evidence-format.md) with sources, retrieval times, source locations and warnings |
| Skill ([SKILL.md](../skills/vulnograph/SKILL.md)) | Read the evidence and write `report.md`, `overview.mmd` and `diagram.mmd`. One canonical file serves both Claude Code and Codex |
| Renderer (later) | Convert Markdown and Mermaid to HTML, SVG, PNG or PDF |

## Sources and their roles

| Source | Role |
| --- | --- |
| CVE Program | Base record: publication state, description, references |
| NVD | Supplementary public analysis: CVSS, CWE, CPE configurations |
| Product or project security advisories | Highest priority for technical details: cause, conditions, fixed versions, workarounds. Currently fetched only when published as a GitHub advisory referenced by the CVE |
| GitHub Security Advisories | Packages, fixed versions and technical descriptions |
| CISA KEV | Separate signal: known exploitation |
| FIRST EPSS | Separate signal: estimated exploitation probability |

Web page content may be inaccurate or in the middle of an update, so retrieval times are always kept.

## Report rules

The report structure, labels and diagram rules are defined in [SKILL.md](../skills/vulnograph/SKILL.md). Regardless of structure, a report must not:

- invent attack conditions or paths that the sources do not state,
- present an unproven attack as demonstrated,
- infer environment-specific risk from a CVSS score,
- call a workaround or mitigation a complete fix.

## Non-goals

- Scanning user environments, SBOM integration, or asset and vulnerability management integration
- Generating, running or validating exploits or proof-of-concept code
- A hosted web service, authentication, databases or multi-tenancy
- High-quality HTML, PDF or PNG layout (planned for later)
- A general-purpose scraper for vendor websites

## Release plan

- **0.1.0-dev.x**: pre-releases for validating the format, the Skill and accuracy. Incompatible changes are allowed and recorded in the [CHANGELOG](../CHANGELOG.md).
- **0.1.0**: the first usable release, when all of the following are met.
- **Later**: renderers, a web UI, matching against SBOMs or environment data, and measuring time to understanding and decision accuracy.

### 0.1.0 definition of done

| Criterion | Status |
| --- | --- |
| `go test`, `go vet` and `go build` pass | Done |
| The CLI reproducibly writes sources, retrieval times, usable evidence and gaps as JSON | Done |
| Tests cover network failure, unknown CVEs, API limits, partial success, malformed responses and source conflicts | Done |
| The Skill runs from Claude Code or Codex and writes the report and diagrams | Done (smoke test on 2026-10-24) |
| For CVE-2026-109618, the report does not confuse the exploit demonstrated on mod_php with the unproven FPM case | Done, covered by tests |
| No unsupported claims, wrong fixed versions, or mitigations described as complete fixes | Checked for the baseline only |
| 10–20 CVEs of different types (RCE, SQL injection, XSS, DoS, …) reviewed, with errors turned into test cases | Open |
| README covers getting started, a sample diagram, limitations, sources and safety notes | Done |

## Remaining work

This is the single list of known open work.

- Review reports for 10–20 CVEs of different types and add fixtures for the errors found, following the [validation plan](validation-plan.md).
- Check Mermaid syntax automatically; diagrams are currently rendered by hand.
- Add more vendor adapters and keep evidence from CVE ADP containers.
- Detect semantic differences in version ranges and scores between sources.
- Validate user-generated reports and diagrams with the CLI (currently only the sample is checked by tests).

## Pre-release smoke test (2026-10-24)

Run on the commit prepared for 0.1.0-dev.1, outside the repository, with the CLI on `PATH` and the Skill installed by `scripts/install-skill.sh`.

| Check | Result |
| --- | --- |
| Live fetch of CVE-2026-109618 | Exit 0; every supported source `ok`; facts identical to the saved fixture |
| Live fetch of CVE-2021-44228 | Exit 0; KEV listed (`ok`) with the catalog entry as a fact |
| Mermaid rendering (mermaid-cli 11.4.2) | README, sample and generated diagrams all render |
| Claude Code 2.1.310: `/vulnograph CVE-2026-109618` | Skill found; live evidence, report and both diagrams written; every cited fact and source exists; diagrams embedded verbatim; mod_php and FPM paths kept separate |
| Claude Code without the CLI on `PATH` | Stopped, wrote no files, and pointed to the installation steps |
| Codex 0.163.0: `$vulnograph CVE-2026-109618` | Skill found; live evidence, report and both diagrams written; every cited fact and source exists; diagrams render; mod_php and FPM paths kept separate |
| Codex without the CLI on `PATH` | Stopped, wrote no files, and pointed to the installation steps |

The runs found two gaps in the Skill, both now fixed:

- Claude Code cited a node with several sources as `F2,F24/S1,S3`, which does not say which fact came from which source.
- Codex did not report the KEV status or the EPSS score because they are signals, not facts; the Skill did not say how to cite them.

## References

- CVE Program API: https://cveawg.mitre.org/api/cve/CVE-2026-109618 and https://github.com/CVEProject/cvelistV5
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- GitHub global advisories: https://docs.github.com/en/rest/security-advisories/global-advisories
- GitHub repository advisories: https://docs.github.com/en/rest/security-advisories/repository-advisories
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS API: https://api.first.org/epss/
- Agent Skills: https://code.claude.com/docs/en/skills (Claude Code) and https://learn.chatgpt.com/docs/build-skills (Codex), checked on 2026-10-24
