# Running mcpsight in CI

`mcpsight verify` is the CI command: it re-scans your servers and exits non-zero
if any drifted from the baseline you committed (`.mcpsight/baseline.json`). This
is `npm audit` for MCP. Put it in the pipeline of any repo whose agents use MCP.

## GitHub Actions

Gate a pull request on drift, and upload findings to GitHub code scanning so they
show up inline on the PR:

```yaml
name: mcpsight
on: [pull_request]

permissions:
  contents: read
  security-events: write   # to upload SARIF

jobs:
  mcpsight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26' }

      # bubblewrap is only needed to scan stdio servers. Remote-only scans skip it.
      - run: sudo apt-get update && sudo apt-get install -y bubblewrap strace

      - name: Build mcpsight
        run: go build -o mcpsight ./cmd/mcpsight

      # verify exits non-zero on drift; scan writes .mcpsight/report.sarif.
      # --offline keeps the gate hermetic: verify's exit code depends only on
      # drift, so the supply-chain network lookups cannot change the result.
      - name: Verify MCP servers against baseline
        run: ./mcpsight verify --from .mcp/config.json --offline

      - name: Scan for the SARIF report
        if: always()
        run: ./mcpsight scan --from .mcp/config.json --dir . || true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .mcpsight/report.sarif
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean. No findings above `--fail-on` (scan), or no drift (verify). |
| `1` | Findings above the `--fail-on` threshold (scan), or drift detected (verify). |
| `2` | Scan error (could not probe, no baseline to verify against, bad flag). |

## Tips

- Commit `.mcpsight/baseline.json` and review its diff in PRs. A changed baseline
  is a changed server.
- `--offline` skips the supply-chain analyzer (the only one that needs network).
  Both `scan` and `verify` accept it.
- `--fail-on critical` makes CI reject only the most serious findings; the default
  is `high`.
- No sandbox backend on the runner? stdio scans are refused (exit 2). Install
  `bubblewrap`, or scan remote targets only.

## Ubuntu 24.04 blocks bubblewrap by default

Ubuntu 24.04 ships `kernel.apparmor_restrict_unprivileged_userns=1`, which stops
unprivileged processes creating user namespaces. bubblewrap needs them, so stdio
scans fail before the server ever starts:

```
bwrap: setting up uid map: Permission denied
bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
```

`ubuntu-latest` on GitHub Actions is 24.04, so a workflow that scans stdio
targets hits this too. Remote-only scans are unaffected.

The usual advice is to set that sysctl to `0`, which removes userns confinement
for every process on the machine. Prefer a scoped AppArmor profile instead, which
exempts only bubblewrap and survives a reboot:

```bash
sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

Verify it works, with the global restriction still on:

```bash
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns   # expect 1
bwrap --unshare-net --unshare-user --ro-bind /usr /usr \
      --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
      --tmpfs /tmp --proc /proc --dev /dev --die-with-parent /bin/echo ok
```
