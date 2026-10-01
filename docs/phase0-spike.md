# Phase 0 spike result: passed

> The goal: prove the risky bit first. Can we run untrusted stdio MCP servers
> under isolation and still observe what they do, before writing any analyzer? This is the record of that spike.

**Date:** 2026-07-15
**Verdict:** PASSED. The sandbox + detection design is viable **without Docker**.

## What was proven

From a Go harness, on a Linux host:

1. Launched an untrusted, deliberately-malicious stdio MCP server inside a
   **bubblewrap** sandbox. No Docker, no daemon, and no root.
2. Completed the MCP `initialize` handshake and retrieved `tools/list` over stdio.
3. **Detected a decoy-credential read (CRITICAL).** The server read seeded decoy
   `~/.ssh/id_rsa`, `~/.aws/credentials`, and `~/.env`.
4. **Detected an outbound network attempt (HIGH).** The server's `connect()` to
   an external host was both captured and blocked (`ENETUNREACH`) by the
   network-unshared namespace.

## Sandbox shape (bubblewrap)

```
bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts \
      --unshare-cgroup --unshare-net --die-with-parent --new-session \
      --ro-bind /usr /usr --symlink usr/bin /bin (…/lib …/lib64 …/sbin) \
      --ro-bind-try /etc/resolv.conf … --ro-bind-try /etc/ssl … \
      --proc /proc --dev /dev --tmpfs /tmp \
      --ro-bind <decoy-home> /home/mcp \
      --bind <out-dir> /out --chdir /home/mcp \
      --setenv HOME /home/mcp --setenv PATH /usr/bin:/bin \
      -- <traced> node /home/mcp/server.js
```

- **Network deny-by-default:** `--unshare-net` gives the process only `lo`.
  External egress fails closed; the attempt is still recorded.
- **Filesystem:** read-only `/usr`, tmpfs `/tmp`, no host mounts except a
  read-only decoy `$HOME` seeded with fake secrets and a bind-mounted out-dir.
- **Decoy credentials** in the fake home are the trap: any read is a finding.

## Detection mechanism

The spike used `strace -f -e trace=network,openat,connect` to an out-of-band log,
parsed on the host, to observe both signals. This proves the signals are
*observable*; it is not the production mechanism.

**Production intent (Phase 2 sandbox hardening):**
- Egress → a netns recording proxy (log DNS + connections, then drop/allow),
  not ptrace, so it is robust against anti-tracing untrusted code.
- Filesystem reads → `fanotify`/`inotify` on the decoy dir (host-side), so a
  bind-mounted decoy read fires a host event without tracing the child.

## Learnings folded into the design

- The DNS `connect()` to the systemd-resolved stub (`127.0.0.53:53`) appears
  alongside real egress and must be **classified as a resolution attempt**,
  distinct from raw external egress, to avoid a misleading finding.
- Mount ordering: you cannot create a mountpoint *file* under a read-only bind.
  Seed per-run files (the server, decoys) into the host dir that becomes the
  read-only bind, rather than binding them individually on top of it.
- `/bin`, `/lib`, `/lib64`, `/sbin` are symlinks into `/usr` on merged-`/usr`
  distros; bind `/usr` and recreate the symlinks with `--symlink`.

## Reproduce

Spike sources are preserved under `docs/phase0-spike/` (`spike.go`,
`evil-server.js`). On a Linux host with `bwrap`, `strace`, and `node`:

```
go build -o spike spike.go && ./spike
```
