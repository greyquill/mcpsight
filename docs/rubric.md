# mcpsight scoring rubric

*Greyquill Software Private Limited · rubric_version: `1` · 2026-07-15*

**A score whose derivation is secret is a score nobody trusts.** This document is
the score. Anyone must be able to recompute a server's grade by hand from its
findings. Every rule here traces to a threat in
[`threat-model.md`](./threat-model.md). Every scan records the `rubric_version`
that produced it, so historical grades stay interpretable when this file changes.

## How the score works

1. A scan produces **findings**, each with a severity:
   `critical | high | medium | low | info`.
2. The server starts at **100 points**. Each finding subtracts a **penalty**
   based on its severity (below). `info` findings never subtract.
3. The score is floored at 0. If there is any `critical` finding, the score is
   also capped at 39, so the server grades F. The report marks a capped score.
4. The score is mapped to a letter grade.
5. `context cost` is reported and can contribute *low*-severity findings for
   egregious bloat, but token count itself does not linearly reduce the score.
   Cost is a number you act on, not a moral failing.

```
score = clamp(100 − Σ penalty(finding), 0, 100)
if any finding is critical: score = min(score, 39)
```

### Severity penalties (rubric v1)

| Severity | Penalty | Meaning |
|---|---:|---|
| critical | 40 | Confirmed exfiltration behavior or an active model-hijack instruction. One is enough to fail a server. |
| high | 20 | A capability or exposure that a realistic attacker turns into compromise. |
| medium | 8 | A meaningful risk that needs a human decision. |
| low | 3 | Hygiene; worth fixing, not alarming. |
| info | 0 | Recorded for transparency; no score impact. |

Multiple findings stack, but each **rule** contributes at most once per tool to
avoid a single issue nuking a score twenty times.

### Grade bands

| Grade | Score |
|---|---|
| A | 90 to 100 |
| B | 75 to 89 |
| C | 60 to 74 |
| D | 40 to 59 |
| F | 0 to 39 |

## Severity assignment by analyzer

Severities below are **defaults**; a scan may raise/lower within documented rules
(e.g. drift severity depends on direction of change). Rule IDs are stable and
namespaced `<analyzer>.<rule>`.

### Capability: observed (sandbox)
| Rule | Default severity | Threat |
|---|---|---|
| `capability.decoy_read`: read a decoy credential file | **critical** | Credential theft |
| `capability.egress_unexpected`: egress not declared by the server's stated function | **high** | Exfiltration |
| `capability.declared_observed_gap`: observed capability exceeds declared | **high** | Hidden capability |
| `capability.not_observed`: the run was not traced (no strace, Docker, or `--no-sandbox`) | **info** | Transparency (checks skipped) |

### Injection (tool descriptions)
| Rule | Default severity | Threat |
|---|---|---|
| `injection.imperative_instruction`: 2nd-person command to the model | **high** | Model hijack |
| `injection.override_instruction`: "ignore previous", "do not tell the user" | **critical** | Model hijack |
| `injection.cross_tool_reference`: names other tools/servers | **high** | Cross-tool hijack |
| `injection.invisible_chars`: zero-width / bidi / homoglyph | **high** | Smuggled instructions |
| `injection.encoded_blob`: base64/hex payload in description | **medium** | Smuggled payload |
| `injection.unrelated_path`: instructs reading files unrelated to function | **high** | Credential/file theft |
| `injection.excessive_length`: description grossly oversized for the tool | **low** | Obfuscation surface |

### Drift (severity by direction of change)
| Rule | Default severity | Threat |
|---|---|---|
| `drift.instruction_added`: description gained an imperative/override | **critical** | Rug-pull |
| `drift.capability_escalated`: e.g. `fs:read → fs:write`, new `path` param | **high** | Rug-pull |
| `drift.tool_added`: a new tool appeared | **medium** | Expanded surface |
| `drift.schema_changed`: input schema changed | **low** | Change awareness |
| `drift.description_shortened`: text removed only | **info** | Noise |

### Supply chain
| Rule | Default severity | Threat |
|---|---|---|
| `supplychain.install_script`: `postinstall`/lifecycle script present | **high** | Arbitrary code on install |
| `supplychain.typosquat`: name near a popular package, or its name under another scope | **high** | Impersonation |
| `supplychain.known_cve`: dependency with a known OSV advisory | **high**/**medium** (by CVSS) | Known-vulnerable dep |
| `supplychain.no_source`: no resolvable/ matching source repo | **medium** | Unauditable |
| `supplychain.single_maintainer`: one publisher | **low** | Bus-factor / account takeover |
| `supplychain.young_package`: first published very recently | **low** | Typosquat vehicle / immaturity |
| `supplychain.metadata_unavailable`: registry metadata could not be fetched | **info** | Transparency (checks skipped) |

### Auth posture (remote)
| Rule | Default severity | Threat |
|---|---|---|
| `authposture.unauthenticated_listing`: `tools/list` without credentials | **high** | Exposed server |
| `authposture.plaintext_http`: endpoint served over `http://` | **high** | Credentials/data in clear |
| `authposture.weak_tls`: negotiated TLS < 1.2 | **medium** | MITM |
| `authposture.no_oauth`: static key / none where OAuth 2.1 expected *(planned)* | **low** | Weak auth model |

### Context cost
| Rule | Default severity | Threat |
|---|---|---|
| `context.schema_bloat`: deeply nested/verbose schema, flattenable | **low** | Invisible token tax |
| `context.oversized_tool`: a single tool dominates the token budget | **info** | Awareness (with remediation) |

## Worked example

A remote server that lists its tools without authentication (high, −20) and
carries a base64 blob in one description (medium, −8) scores `100 − 20 − 8 = 72`,
**grade C**. Add a confirmed decoy read (critical, −40) and the arithmetic gives
32, **grade F**. A server whose only finding is that decoy read would compute to
60, but the critical cap holds it at 39, also **grade F**. Every subtraction and
the cap are shown in the report, so the arithmetic is yours to check.

## Changing the rubric

- Bump `rubric_version` (integer) on any change to penalties, bands, or rule
  severities. Never silently re-grade history.
- Adding a rule at an existing severity does not require a new major treatment,
  but still bumps `rubric_version`.
- Document the change in this file's git history; the index surfaces which
  rubric version graded each historical scan.
