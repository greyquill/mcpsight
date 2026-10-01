# Contributing to mcpsight

Thanks for helping X-ray the MCP ecosystem. mcpsight is Apache-2.0 and means to
stay a friend to server maintainers: we grade servers, never people, and we ship
a remediation with every finding.

## Development

Requirements: **Go 1.26+**. To scan stdio servers (and run the observed-capability
and end-to-end tests) you also need Linux with **bubblewrap** and **strace**
(`apt-get install bubblewrap strace`). On macOS/Windows you can develop and run
the unit tests and remote scans; stdio scanning is refused without a sandbox.

```console
$ make build      # -> bin/mcpsight
$ make test       # go test ./...
$ go vet ./...
$ gofmt -w .
```

Tests are **hermetic**: the Postgres store tests skip unless `MCPSIGHT_TEST_DSN`
is set, and the sandbox/stdio behavior is covered by unit tests plus (on Linux)
end-to-end tests. Keep it that way. No test should require the network or a
database to pass by default.

## Where things live

```
cmd/mcpsight/         CLI entrypoint
cmd/mcpsight-index/   the Registry Security Index service
internal/probe/       runs a target, produces the canonical manifest
internal/sandbox/     bubblewrap isolation + decoy/egress observation
internal/manifest/    canonicalization, hashing, diffing (the drift spine)
internal/analyze/*    one package per analyzer  ── see docs/analyzers/README.md
internal/score/       the rubric implementation  ── see docs/rubric.md
internal/render/      terminal / json / sarif / markdown
internal/store/       sqlite baselines (local) + postgres (index)
testdata/servers/     deliberately malicious fixtures (the spec)
```

## The two documents that govern the score

Before changing what mcpsight flags or how it grades, read
[`docs/threat-model.md`](docs/threat-model.md) and [`docs/rubric.md`](docs/rubric.md).
The score is a **consequence of a stated threat model**, and the rubric is
**published and versioned**. Anyone must be able to recompute a grade by hand.
Any change to a penalty, band, or rule severity **bumps `RubricVersion`**.

## Adding an analyzer

This is the most common contribution and is designed to be a self-contained PR.
Follow [`docs/analyzers/README.md`](docs/analyzers/README.md).

## Pull requests

- One logical change per PR; include tests and, for new findings, a fixture.
- Keep `gofmt`, `go vet`, and `make test` green (CI enforces them).
- Match the surrounding code's style; write comments that explain *why*, not *what*.
- By contributing you agree your work is licensed under Apache-2.0.

## Reporting issues in a scanned server

Found a real problem in a public MCP server via mcpsight? Grade the server, not
the person: open a friendly issue on *their* repo with the finding and the
`mcpsight scan …` command to reproduce it. It is free security review, so frame it
that way.
