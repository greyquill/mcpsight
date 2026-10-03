# Security policy

[Greyquill Software](https://www.greyquill.io) maintains mcpsight. It runs code from
MCP servers you do not control, so a bug in mcpsight can put your machine at risk.

## Reporting a vulnerability

Please report it privately. Do not open a public issue.

Use either private channel:

- **GitHub:** open the [Security tab](https://github.com/greyquill/mcpsight/security)
  and choose **Report a vulnerability**. Only the maintainers can see the report.
- **Email:** write to [contact@greyquill.io](mailto:contact@greyquill.io) and start
  the subject with "MCPsight security".

Tell us what you can:

- The mcpsight version (`mcpsight version`) and your OS.
- What you did, what happened, and what you expected.
- A proof of concept, if you have one. A minimal MCP server that triggers the
  problem is ideal.

## What happens next

- We confirm we received your report within 3 working days.
- We tell you whether we accept it, and our plan, within 10 working days.
- We fix accepted issues in a new release and publish a GitHub security advisory.
- We credit you in the advisory, unless you ask us not to.

Please give us 90 days, or until a fix ships, before you disclose publicly. If you
think users are being harmed right now, say so in the report and we will move faster.

## In scope

Anything that lets an MCP server you scan affect the machine running mcpsight:

- Escaping the sandbox, or reaching real files, credentials, or environment
  variables from inside it.
- Running code during a scan without a sandbox, unless you passed `--no-sandbox`.
- Making mcpsight hang, crash, or exhaust memory despite the resource limits.
- Injecting terminal control sequences or Markdown into reports.
- Secrets from your config (env values, headers) appearing in reports.
- Tampering with a release binary or its signature.

## Out of scope

- An MCP server that mcpsight grades wrongly. Open a normal issue for that.
- Detection gaps the [threat model](docs/threat-model.md) already lists, such as
  evading `strace`-based observation.
- Anything that needs `--no-sandbox`. That flag exists for trusted code only.

## Supported versions

We fix security issues in the latest release only. Upgrade to get a fix.

## Verifying a release

Every release ships a `checksums.txt`, signed with [Sigstore](https://www.sigstore.dev)
from our GitHub release workflow, plus a build provenance attestation for each
archive. See [Verify a download](https://mcpsight.dev/docs/verify-download.html).
