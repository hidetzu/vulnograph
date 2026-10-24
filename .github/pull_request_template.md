## Summary

<!-- What changed and why. Link related issues. -->

## Checklist

- [ ] `gofmt -l cmd internal examples` prints nothing, and `go test -race ./...` and `go vet ./...` pass
- [ ] Each fix has a regression test (a fixture under `testdata/anomalies` for malformed upstream data)
- [ ] Every new fact comes from a validated source and has a `source_pointer`
- [ ] Contract changes bump `SchemaVersion` and update the Skill
- [ ] Golden files and examples are regenerated and reviewed, if the output changed
- [ ] CHANGELOG.md "Unreleased" is updated for user-visible changes
- [ ] No secrets, tokens or local paths are included
