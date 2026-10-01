# mcpsight threat model

*Greyquill Software Private Limited · v0.1 · 2026-07-15*

The score is a consequence of this threat model, not a vibe. Every rubric point
in [`rubric.md`](./rubric.md) traces back to a threat named here. If a check does
not map to a threat below, it does not belong in the score.

## 1. What mcpsight defends

A developer or team is about to **install, or has already installed, an MCP
server** and wires it into an agent that holds real capability: file access,
shell, credentials, network, and a model that will follow instructions embedded
in tool metadata. The decision mcpsight informs is *pre-deployment*:

- **Should I install this server?**
- **Did a server I already trust change under me?**

mcpsight is a **risk-surface and change detector**, run in ~30 seconds on a
laptop or in CI. It is explicitly **not** a malware scanner and does not claim to
detect novel malicious code (see [Non-goals](#7-explicit-non-goals)).

## 2. Assets

| Asset | Why it matters |
|---|---|
| Developer credentials on the host (`~/.ssh`, `~/.aws`, `.env`, cloud tokens) | The direct target of the documented MCP exfiltration attacks. |
| The agent's action space | A poisoned tool description steers the *model*, turning any connected capability (shell, fs, network) into the attacker's. |
| Host filesystem & network | Untrusted server code runs on install/first-run. |
| The token budget | Tool definitions are injected into every request; bloat is a real, ongoing cost. |
| Trust in an already-installed server | Rug-pulls exploit trust established at install time. |

## 3. Adversaries and trust boundaries

1. **The server author** may be malicious from day one (typosquat, poisoned
   description) or may **turn malicious later** (rug-pull after adoption).
2. **A compromised dependency** of an otherwise-honest server.
3. **A network-adjacent attacker** for remote servers (unauthenticated tool
   listing, weak/absent TLS).
4. **The untrusted code itself**, executing during probe. The sandbox treats it
   as hostile. **The sandbox is a trust boundary mcpsight must not leak across.**

The user running mcpsight is trusted. The host it runs on is trusted *except*
for the code under scan, which is contained (see §6).

## 4. Attacker goals → the checks that catch them

| Attacker goal | Vector | Analyzer / signal |
|---|---|---|
| Steal host credentials | Server reads `~/.ssh/id_rsa` etc. on init | **Capability (observed):** decoy-credential read in sandbox → CRITICAL |
| Exfiltrate data | Outbound connection on init | **Capability (observed):** recorded egress attempt; declared-vs-observed gap |
| Hijack the model | Imperative instructions hidden in a tool *description* | **Injection:** imperative 2nd-person text, "ignore previous", "do not tell the user" |
| Cross-tool hijack | Description references *other* tools/servers by name | **Injection:** cross-reference rule |
| Smuggle instructions past human review | Zero-width / bidi / homoglyph / base64 in descriptions | **Injection:** invisible-character & encoded-blob rules |
| Bait-and-switch trusted server | Description/schema/capability changes after adoption | **Drift:** canonical-manifest diff, severity by direction of change |
| Impersonate a popular server | Typosquatted package name | **Supply chain:** edit distance, and same name under another scope, vs a curated list of popular packages |
| Ship unauditable code | No source, install scripts, deep deps, known CVEs | **Supply chain:** source availability, `postinstall`, OSV.dev, maintainer signal |
| Reach an exposed remote server | `tools/list` with no auth; weak TLS | **Auth posture:** unauthenticated-probe result, TLS basics |
| Impose an invisible tax | Verbose/bloated tool schemas | **Context cost:** per-model token count, schema-bloat remediation |

## 5. The rug-pull threat (why drift is first-class)

The manifest is **canonicalized** (deterministic key ordering, whitespace,
Unicode normalization) and hashed (SHA-256). The baseline is committable to git
(`.mcpsight/baseline.json`); richer history lives in local SQLite. `mcpsight
verify` fails CI when the live manifest drifts from the committed baseline.
**Severity derives from the direction of change**: a shortened description is
noise; a description that *acquires* an imperative instruction, or a capability
that escalates `fs:read → fs:write`, is critical. This is the feature that keeps
the tool installed after the first scan.

## 6. The sandbox as a trust boundary

Probing a stdio server **executes untrusted code**. Requirements, and how the
Phase 0 spike met them (see [`phase0-spike.md`](./phase0-spike.md)):

- **Isolation without Docker on the dev host:** bubblewrap with
  `--unshare-{user,pid,ipc,uts,cgroup,net}`, read-only `/usr`, tmpfs `/tmp`, no
  host mounts except a read-only decoy `$HOME` and an out-of-band trace dir.
  Docker is permitted **only** on a dedicated Linux runner, and
  only for `docker:` OCI targets and the batch index runner.
- **Network deny-by-default:** the process gets only loopback. Egress fails
  closed; the *attempt* is still recorded (`--allow-net` opens it deliberately
  for servers that need the network to initialize, and that fact is reported).
- **Decoy credentials** seeded in the fake home. **Any read is a finding.** This
  is the trap that catches the exact exfiltration pattern the typosquat attacks used.
- **Fail safe, never silent:** if no sandbox backend is available, mcpsight
  refuses to scan stdio targets and says so. `--no-sandbox` exists, prints a red
  warning, and is never the default. Remote and static-only analysis still run.
- **DNS-resolution attempts** (e.g. to the systemd-resolved stub) are classified
  separately from raw external egress, to avoid a misleading finding.
- **Resource limits** bound hostile code: the bwrap sandbox caps per-process
  address space, CPU seconds, open files, and file size (`prlimit`) plus a
  size-capped `/tmp` tmpfs; the Docker runner uses cgroup `--memory`/`--cpus`/
  `--pids-limit`. A memory-exhaustion attempt is killed and the host is unharmed.

Residual risk: a kernel/userns escape, or a covert channel through an allowed
syscall, could cross the boundary. We default-deny network, limit resources, and
never mount host secrets. We do not claim the sandbox is unbreakable; we claim it
is default-deny and observable.

**Remaining hardening (tracked):** observed-capability tracing currently uses
`strace` inside the sandbox, which anti-ptrace code could evade. The hardened
design moves observation out of the sandbox (a netns recording proxy for egress
and `fanotify` for decoy reads). That also frees a seccomp profile to deny
`ptrace`/`mount`/`kexec`/module-loading outright. This needs privileged setup and
is future work; `strace` is adequate for the stated threat model (we do not claim
to defeat a determined evader, only to observe honest-to-careless behavior).

## 7. Explicit non-goals

Stated plainly, because overclaiming destroys credibility permanently:

- **Not a malware scanner.** We do not detect novel malicious code. We detect
  *risk surface* and *change*.
- **Not a gateway.** No proxying of live traffic in v1.
- **Not a registry.** We do not host or replace the official registry.
- **Not an eval framework.** We measure cost and reach, not whether a tool is *good*.

## 8. Trust in the output

The rubric is **published and versioned**; anyone can recompute a score by hand
from the findings. The public index is generated by the exact code the user runs.
Every scan records the `mcpsight_version` and `rubric_version` that produced it, so
grades stay interpretable when the rubric evolves. **Reproducibility is the
credibility.**
