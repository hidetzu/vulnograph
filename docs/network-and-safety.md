# Network access and safety

vulnograph treats every external response as untrusted data. This page describes what the CLI connects to and how it limits that access. To report a vulnerability in vulnograph itself, see [SECURITY.md](../SECURITY.md).

## What is fetched

| Host | Used for |
| --- | --- |
| `cveawg.mitre.org` | CVE Program API record |
| `services.nvd.nist.gov` | NVD API 2.0 record |
| `api.github.com` | GitHub Security Advisories referenced by the CVE or NVD record |
| `www.cisa.gov` | The complete CISA KEV catalog |
| `api.first.org` | FIRST EPSS score |

GitHub advisories are fetched only when a reference URL has the exact form of a GitHub advisory page (`github.com/advisories/GHSA-…` or `github.com/<owner>/<repo>/security/advisories/GHSA-…`). Other references, including vendor web pages, are recorded with the reason they were not fetched. The CLI does not follow links inside response bodies, search for advisories exhaustively, or import CVE ADP containers.

## Connection limits

- HTTPS only, to the fixed host allowlist above, on port 443.
- Every DNS answer must be a public address before any connection is made; private, loopback, link-local and other special-use ranges are rejected. Each connection is pinned to a validated address.
- HTTP redirects and proxies are disabled.
- At most 16 MiB per response, 30 seconds per HTTP request, 3 minutes per run, and 32 advisory fetches per run.

## Rate limits and retries

- Requests to the same host are spaced at least 1 second apart. For NVD, 6 seconds without an API key and 600 ms with one.
- HTTP 429, HTTP 5xx and network failures are tried up to 3 times. A `Retry-After` longer than 30 seconds is recorded as a failure instead of waiting.
- Rate limiting is per process; there is no coordination across concurrent processes.

## Credentials

`NVD_API_KEY` and `GITHUB_TOKEN` are optional and read only from environment variables. Do not pass them as command arguments. The NVD key is sent only to NVD, and the GitHub token only to the GitHub API. Neither is written to the output, and network error details are not copied into the JSON.

## Untrusted content

- Descriptions and advisory bodies are kept as JSON strings. Instructions or code inside them are never executed by the CLI, and the Skill is told to treat them as data.
- The Skill must check every report sentence and diagram node against the evidence, and must not put HTML, links, click actions or Mermaid init directives into diagrams.
- Saved API snapshots under `testdata` and `examples` reflect the time they were retrieved and are not current vulnerability information.
