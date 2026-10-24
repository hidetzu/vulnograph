# Contributing to vulnograph

Thank you for your interest. vulnograph puts the accuracy of vulnerability information and the quality of explanations ahead of new features. Contributions that make evidence more correct or more traceable are especially welcome.

Issues and pull requests may be written in English or Japanese.

## Before you start

- Report a security vulnerability in vulnograph itself privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.
- For a wrong or misleading value in evidence or a report, open a "Data accuracy" issue with the CVE ID, the source, and what the source actually says.
- For a larger change, open an issue first so the approach can be agreed before you write code.

## Development

Requires Go 1.24 or later. The CLI uses only the standard library; do not add dependencies without discussing it in an issue.

```bash
gofmt -l cmd internal examples   # must print nothing
go test -race ./...
go vet ./...
go build ./...
```

Tests run offline. Do not add tests that call external APIs.

## Rules for changes

- **Keep every fact traceable.** A fact must come from a successfully validated source and carry a `source_pointer` into that source's body. Validate a response completely before adding any fact from it.
- **Distinguish failure from absence.** A truncated, malformed or empty response is `fetch_failed` or `unknown`, never `not_found`.
- **The CLI does not interpret.** Interpretation, summarization and diagrams belong to the Skill. The CLI must not resolve differences between sources.
- **Add a regression test for every fix.** Reproduce malformed upstream data with a fixture under [testdata/anomalies](testdata/anomalies) when possible. Fixtures that are not real snapshots must be clearly synthetic.
- **Contract changes.** The Go types in [internal/evidence](internal/evidence/evidence.go) are the contract. An incompatible change must bump `SchemaVersion`, update the Skill, and be recorded in [CHANGELOG.md](CHANGELOG.md).
- **Golden files.** If a change intentionally alters the baseline output, regenerate it and review the diff:

  ```bash
  go run ./cmd/vulnograph fetch CVE-2026-109618 --fixture testdata/CVE-2026-109618 \
    --output testdata/CVE-2026-109618/evidence.golden.json
  cp testdata/CVE-2026-109618/evidence.golden.json examples/CVE-2026-109618/evidence.json
  ```

  If Fact IDs change, update the sample report and diagrams; `go test ./examples` checks their citations.
- **Skill and diagrams.** Diagram nodes must cite a Fact ID and its source, or be marked unknown (不明). Never add attack paths, payloads or exploitation steps that the sources do not state.
- **Never commit secrets.** API keys and tokens are read from environment variables only.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <subject>`, with types `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build` or `revert`.
- Keep pull requests focused, and describe what changed, why, and how it was tested.
- Add an entry under "Unreleased" in CHANGELOG.md for user-visible changes.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
