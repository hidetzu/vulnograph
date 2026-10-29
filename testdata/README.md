# Test data

All tests run offline against the data in this directory.

## CVE-2026-109618: baseline snapshots

Unmodified API responses retrieved over HTTPS with the URLs the CLI uses: `cve.json` (CVE Program), `nvd.json` (NVD), `GHSA-w8hw-w9fx-j79w.json` (PHP's repository advisory), `kev.json` (the complete CISA KEV catalog) and `epss.json` (FIRST EPSS). `manifest.json` records the retrieval time, and the SHA-256 of each file appears in the generated evidence.

The KEV catalog is stored in full so that "not listed" can be reproduced from a complete catalog. A live run on the same day fetched every supported source successfully.

`evidence.golden.json` is the reviewed CLI output for these files; CI requires the output to match it exactly. Tests also check that:

- the patched versions per branch are 8.2.35, 8.3.36, 8.4.27 and 8.5.12,
- the advisory's distinction between the exploit demonstrated on mod_php and the unproven FPM case is preserved,
- every fact's `source_pointer` resolves to its value in the raw file.

These snapshots reflect the time they were retrieved, not current information. Rights to their content belong to the respective providers.

## synthetic: fictional baseline

Fictional data for testing states and conflict candidates. It is not related to any real CVE that may use the same ID. The CVE record references a fictional Cisco advisory, `cisco-sa-synthetic-AbCd`; `cisco-csaf-index.txt` is the CSAF index that lists it and `cisco-sa-synthetic-abcd.json` is its CSAF document, both in the form the CLI reads from Cisco's distribution.

## anomalies: malformed input

Each directory contains only the response files that override `synthetic`. The expected results are in the table in [anomaly_test.go](../internal/sources/anomaly_test.go). All data is fictional.

| Case | Reproduces |
| --- | --- |
| kev-count-mismatch | KEV `count` does not match the number of entries (truncated catalog) |
| kev-count-missing | KEV has no `count` |
| kev-count-fraction | KEV `count` is fractional and would match if truncated |
| kev-count-negative | KEV `count` is negative |
| kev-entry-without-cve | A KEV entry has no `cveID` |
| kev-duplicate-listing | The same CVE is listed twice in KEV |
| nvd-id-only | NVD returns a record with only an ID and status |
| nvd-total-mismatch | NVD `totalResults` does not match the returned records |
| nvd-total-fraction | NVD `totalResults` is fractional with no records (0 if truncated) |
| nvd-total-missing | NVD has no `totalResults` |
| nvd-only-reserved | The CVE record is RESERVED and the NVD record has no content |
| ghsa-withdrawn | The GitHub advisory is withdrawn |
| ghsa-id-mismatch | The advisory ID differs from the reference URL |
| ghsa-id-missing | The advisory has no ID |
| ghsa-id-wrong-type | The advisory ID is not a string |
| ghsa-duplicate-patch | `patched_versions` and `first_patched_version` are the same |
| csaf-id-mismatch | The CSAF tracking ID differs from the advisory in the reference URL |
| csaf-id-missing | The CSAF document has no tracking ID |
| csaf-cve-missing | The CSAF document lists a different CVE only |
| csaf-version-unsupported | The CSAF version is not 2.x |
| csaf-draft | The CSAF tracking status is `draft` |
| csaf-product-undefined | A product status names an ID the product tree does not define |
| csaf-fixed-status | The CSAF document lists `fixed` and `first_fixed` products |
| csaf-multi-cve | The CSAF document covers two CVEs with different product statuses |
| csaf-index-unlisted | The CSAF index does not list the advisory |
| csaf-index-malformed | The CSAF index contains a path outside the distribution |
