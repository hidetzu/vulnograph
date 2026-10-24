# Evidence format

`vulnograph fetch` writes one JSON document per CVE. This page describes `schema_version: "0.2"`. The [Go type definitions](../internal/evidence/evidence.go) are the source of truth; incompatible changes bump the version and are recorded in the [CHANGELOG](../CHANGELOG.md).

The document only records what each source says. It never merges differing statements, and never decides whether a particular environment is vulnerable.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Version of this format |
| `cve_id` | Normalized CVE ID |
| `state` | Overall state of the CVE record (see [state](#state)) |
| `fetched_at` | Time the collection started (UTC). For fixtures, the time recorded in the fixture manifest |
| `sources` | Every source that was retrieved or considered, with its status |
| `facts` | Every value taken from a source. Values are stored only here |
| `cvss`, `affected`, `fixed` | Arrays of Fact IDs, as indexes into `facts` |
| `kev`, `epss` | Exploitation signals (see [signals](#signals-kev-and-epss)) |
| `conflicts` | Candidate mismatches between sources |
| `warnings` | Messages a reader must check before drawing conclusions |

## Sources

```json
{
  "id": "S3",
  "kind": "ghsa",
  "title": "ghsa",
  "url": "https://api.github.com/repos/php/php-src/security-advisories/GHSA-w8hw-w9fx-j79w",
  "published_at": "2026-10-21T13:34:25Z",
  "retrieved_at": "2026-10-24T04:48:16.323813Z",
  "status": "ok",
  "sha256": "516c90622d089808abe655ddfb49ba725e2392f0f9254ba566bc5e098c3926e3"
}
```

`kind` is one of `cve_record` (CVE Program API), `nvd` (NVD API 2.0), `ghsa` (GitHub Security Advisory), `cisa_kev`, `first_epss` or `reference`. A `reference` is a URL listed by a CVE or NVD record that vulnograph does not fetch; it is kept with its `reason` so readers can follow it themselves. `sha256` is the digest of the retrieved body, and `reason` explains any status other than `ok`.

### Status

| status | Meaning |
| --- | --- |
| `ok` | Retrieved and validated; for a signal, listed |
| `not_found` | The source has no record or listing |
| `unknown` | Undetermined, not retrieved, or unpublished |
| `fetch_failed` | Network, HTTP or JSON failure, or a response that failed validation (for example a count that does not match its entries, or a record without content) |
| `not_applicable` | Not applicable, such as a REJECTED CVE |

A response is validated completely before any fact is taken from it, so a failed source never contributes facts.

## Facts

```json
{
  "id": "F33",
  "field": "fixed",
  "value": { "package": { "ecosystem": "php", "name": "php-src" }, "version": "8.2.35" },
  "source_ids": ["S3"],
  "source_pointer": "/vulnerabilities/0/patched_versions",
  "original": "8.2.35"
}
```

| Field | Meaning |
| --- | --- |
| `id` | Fact ID, such as `F33`. Reports and diagrams cite facts by this ID |
| `field` | What the value describes (see below) |
| `value` | The value, as structured JSON |
| `source_ids` | The source the value came from |
| `source_pointer` | [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901) to the value's location in that source's retrieved body |
| `original` | Present only when `value` is normalized or extracted; the value exactly as it appears at `source_pointer` |

Fields: `publication_state`, `description`, `affected`, `fixed`, `cvss`, `weakness`, `reference`, `nvd_status`, `advisory_summary`, `advisory_description`, `advisory_severity`, `advisory_state`, `advisory_withdrawn` and `known_exploitation`. Values such as CVSS metrics and NVD CPE configurations are kept in their original structure rather than flattened.

Do not use an advisory with `advisory_withdrawn`, or with an `advisory_state` other than `published`, as current evidence.

## State

| state | Meaning |
| --- | --- |
| `ok` | The CVE record is PUBLISHED and valid |
| `not_found` | The CVE Program API returned 404. This does not distinguish a reserved CVE from a nonexistent one |
| `unknown` | RESERVED, an unrecognized state, or the record could not be retrieved |
| `not_applicable` | REJECTED |

## Signals: KEV and EPSS

```json
"kev": { "status": "not_found", "source_ids": ["S8"] },
"epss": { "status": "ok", "source_ids": ["S9"], "score": 0.1162, "as_of": "2026-10-23" }
```

- `kev.status` is `ok` when the CVE is in the CISA Known Exploited Vulnerabilities catalog, and `not_found` only when a complete catalog was retrieved and the CVE is not in it. Absence does not mean the vulnerability is not exploited.
- `epss.score` is FIRST's estimated probability of exploitation, observed on `as_of`. It is not a severity score.
- When either cannot be retrieved, the signal is `unknown` and its source is `fetch_failed`.

## Conflicts and warnings

`conflicts` lists descriptions in the same language whose wording differs between sources. A difference in wording is not necessarily a contradiction; the Skill or a human decides. Translations are not compared.

`warnings` reports failed sources, partial evidence, withdrawn advisories and similar conditions. Always read them, even when the exit code is 0.
