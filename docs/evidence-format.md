# Evidence format

`vulnograph fetch` writes one JSON document per CVE. This page describes `schema_version: "0.3"`. The [Go type definitions](../internal/evidence/evidence.go) are the source of truth; incompatible changes bump the version and are recorded in the [CHANGELOG](../CHANGELOG.md).

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

`kind` is one of `cve_record` (CVE Program API), `nvd` (NVD API 2.0), `ghsa` (GitHub Security Advisory), `csaf` (a vendor advisory in CSAF 2.0 form, currently Cisco), `csaf_index` (the directory index used to locate a CSAF document; it contributes no facts), `cisa_kev`, `first_epss` or `reference`. A `reference` is a URL listed by a CVE or NVD record that vulnograph does not fetch; it is kept with its `reason` so readers can follow it themselves. `sha256` is the digest of the retrieved body, and `reason` explains any status other than `ok`.

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
  "id": "F37",
  "field": "fixed",
  "value": { "package": { "ecosystem": "php", "name": "php-src" }, "version": "8.2.35" },
  "source_ids": ["S3"],
  "source_pointer": "/vulnerabilities/0/patched_versions",
  "original": "8.2.35"
}
```

| Field | Meaning |
| --- | --- |
| `id` | Fact ID, such as `F37`. Reports and diagrams cite facts by this ID |
| `field` | What the value describes (see below) |
| `value` | The value, as structured JSON |
| `source_ids` | The source the value came from |
| `source_pointer` | [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901) to the value's location in that source's retrieved body |
| `original` | Present only when `value` is normalized or extracted; the value exactly as it appears at `source_pointer` |

Fields: `publication_state`, `description`, `affected`, `fixed`, `affected_bound`, `cvss`, `weakness`, `reference`, `nvd_status`, `advisory_summary`, `advisory_description`, `advisory_note`, `advisory_severity`, `advisory_state`, `advisory_withdrawn`, `remediation`, `threat` and `known_exploitation`. Values such as CVSS metrics and NVD CPE configurations are kept in their original structure rather than flattened.

Do not use an advisory with `advisory_withdrawn`, or with an `advisory_state` other than `published` (GitHub) or `final` (CSAF), as current evidence.

### Fixed versions

A `fixed` fact is recorded only where a source states a fixed version. From a GitHub advisory, `patched_versions` and `first_patched_version`. From the CVE record, the `versions` list of each `affected` product, for a product that the record marks affected somewhere, in three shapes:

| Shape in the record | Fact |
| --- | --- |
| A single version with `status: unaffected` | That version |
| A `changes` entry with `status: unaffected` inside a range | Its `at`, with the range's `version` as `branch` |
| An `affected` range with `lessThan`, when the product's `defaultStatus` is `unaffected` | The `lessThan` value, with the range's `version` as `branch`; the record declares versions outside its ranges unaffected |

Each fact carries `vendor`, `product` and `packageName` when present, `version`, and `original` with the version text at `source_pointer`.

```json
{
  "id": "F4",
  "field": "fixed",
  "value": { "branch": "8.2.*", "packageName": "php-src", "product": "PHP", "vendor": "PHP Group", "version": "8.2.35" },
  "source_ids": ["S1"],
  "source_pointer": "/containers/cna/affected/0/versions/0/lessThan",
  "original": "8.2.35"
}
```

No `fixed` fact is derived from `lessThanOrEqual` (inclusive), from a wildcard bound such as `1.*`, from `All`, or from NVD CPE ranges (`versionEndExcluding` is NIST's configuration analysis, not a statement of the fix).

### Affected bounds

When `defaultStatus` is absent or `unknown`, the record says nothing about the versions at and above a `lessThan`, so that bound is not a fix. It is recorded as an `affected_bound` fact with the same shape as a `fixed` fact (`vendor`, `product`, `packageName`, `branch`, `version`, `original`), so the Skill can present it as an estimate with its own citation. A bound equal to a version the same product entry already states as fixed is not repeated. `affected_bound` has no index in the document; `fixed` never contains one.

```json
{
  "id": "F30",
  "field": "affected_bound",
  "value": { "branch": "10.0.26100.0", "product": "Windows 11 Version 24H2", "vendor": "Microsoft", "version": "10.0.26100.9711" },
  "source_ids": ["S1"],
  "source_pointer": "/containers/cna/affected/7/versions/0/lessThan",
  "original": "10.0.26100.9711"
}
```

### Vendor advisories (CSAF)

A reference to a Cisco Security Advisory page (`sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-…`, or the older `tools.cisco.com` form) names the advisory but not where its machine-readable form lives. The CLI reads Cisco's CSAF index (`www.cisco.com/.well-known/csaf/index.txt`, recorded as a `csaf_index` source), looks the advisory up by its lower-cased ID, and retrieves the listed `year/<id>.json` document as a `csaf` source. The advisory web page itself is never fetched. An advisory missing from the index, or an index that fails to validate, leaves the reference as an unfetched `reference` with the reason.

The document is validated before any fact is taken: `csaf_version` must be `2.0` (the field layout read is the 2.0 one, so a 2.1 document is rejected rather than read with its weaknesses and scores missing), `document.tracking.id` must equal the advisory ID in the reference (case-insensitively), and `vulnerabilities` must contain an entry whose `cve` is this CVE. Only the entries for this CVE are read, because one advisory may cover several CVEs with different product statuses. The facts and their pointers:

| Fact | From |
| --- | --- |
| `advisory_state` | `/document/tracking/status`. `final` is the published state; `draft` and `interim` produce a warning, and a document without a status produces a warning and no `advisory_state` |
| `advisory_severity` | `/document/aggregate_severity/text`, when present |
| `advisory_summary` | The vulnerability entry's `title`, or `/document/title` when it has none |
| `advisory_description` | The `text` of each note with category `summary` or `description`, in the document and in the entry |
| `advisory_note` | Every other note except `legal_disclaimer`, with its `category`, `title` and `text`. Cisco writes fixed releases, workarounds and exploitation notes here, so read these before concluding that a fix is unstated |
| `weakness` | The entry's `cwe` |
| `cvss` | Each `cvss_v2`, `cvss_v3` and `cvss_v4` object under the entry's `scores` |
| `affected` | Each product ID under `product_status.known_affected`, `first_affected`, `last_affected`, `known_not_affected`, `under_investigation` and `recommended`, with the status it was listed under. `recommended` is a vendor recommendation, not a statement that the release contains the fix |
| `fixed` | Each product ID under `product_status.fixed` and `first_fixed` |
| `remediation` | Each entry of `remediations`, as it appears (category such as `vendor_fix` or `workaround`, details, URL, product IDs) |
| `threat` | Each entry of `threats`, as it appears (category such as `exploit_status`, details) |

A product status fact carries `status`, the `product_id` as `original`, and what the `product_tree` says about that ID: its `name`, and `branches` (the path of `category`/`name` pairs from the vendor down to the version) or the `relationship` that composes it. Read `status` before treating a fact as affected; `known_not_affected` is listed under `affected` so that the vendor's negative statement keeps its citation, and this is why format 0.3 is not a drop-in for readers that took every entry of the `affected` index as affected. A product ID the tree does not define is kept with the ID alone and reported in `warnings`. A product ID listed in more than one CSAF status group (affected, not affected, fixed, under investigation) is kept under each status and reported in `warnings` as contradicting; `recommended` belongs to no group.

```json
{
  "id": "F29",
  "field": "affected",
  "value": {
    "status": "known_affected",
    "product_id": "CSAFPID-286755",
    "name": "13.0.0-392",
    "branches": [
      { "category": "vendor", "name": "Cisco" },
      { "category": "product_family", "name": "Cisco Secure Email" },
      { "category": "product_version", "name": "13.0" },
      { "category": "service_pack", "name": "13.0.0-392" }
    ]
  },
  "source_ids": ["S4"],
  "source_pointer": "/vulnerabilities/0/product_status/known_affected/1",
  "original": "CSAFPID-286755"
}
```

Document references, acknowledgments and vendor bug IDs are not collected.

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
