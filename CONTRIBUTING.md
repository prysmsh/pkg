# Contributing to prysmsh/pkg

Thanks for your interest in contributing. This document covers how to run tests, add packages, and submit changes.

## Running tests

```bash
go test ./...
```

All packages must have tests. New code should include tests.

## Adding a new package

1. Create a new directory under `pkg/` (e.g. `pkg/newpkg/`).
2. Add `doc.go` or a `.go` file with a package-level doc comment describing the package.
3. Add `newpkg_test.go` with tests.
4. Update `README.md` to document the new package in the Packages table and add a usage example.

## Pull request expectations

- **Tests** – New code must have tests. Bug fixes should include a test that reproduces the bug.
- **No breaking changes** – Avoid breaking the public API. If breaking changes are necessary, we will bump the major version.
- **Documentation** – Public functions and types should have godoc comments.

## Questions

- **Bug reports and feature requests:** [GitHub Issues](https://github.com/prysmsh/pkg/issues)
- **Prysm community:** [prysm.sh](https://prysm.sh)
