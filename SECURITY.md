# Security Policy

## Supported versions

vulnograph is in early development (0.1.0-dev.x). Only the latest release and the `main` branch receive security fixes.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, discussions or pull requests.

Report them privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/hidetzu/vulnograph/security/advisories/new)). Include:

- the affected version or commit,
- steps to reproduce, or a proof of concept that does not target third-party systems,
- the impact you expect.

You should receive an acknowledgement within 7 days. We will keep you informed of the fix and coordinate disclosure with you, and credit you in the advisory unless you prefer otherwise.

## Scope

In scope are vulnerabilities in vulnograph itself, for example:

- bypassing the host allowlist, public-IP validation or redirect blocking (SSRF),
- leaking `NVD_API_KEY` or `GITHUB_TOKEN` to unintended hosts or into output,
- path traversal or unsafe file writes through CLI arguments or fixtures,
- untrusted source content causing the Skill's generated reports or Mermaid diagrams to execute code, load external resources or include unsafe HTML.

Out of scope:

- vulnerabilities in the products described by CVEs; report those to the respective vendors,
- inaccurate data from upstream sources (CVE Program, NVD, GitHub, CISA, FIRST); report those upstream, or open a "Data accuracy" issue if vulnograph misrepresents them.
