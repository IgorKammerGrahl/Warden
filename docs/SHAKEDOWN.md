# Real-peer shakedown

Everything before this ran warden against fixtures warden's authors wrote. This
ran it against `@modelcontextprotocol/server-filesystem` 2026.7.10 — a server
we did not write — driven by a Claude Code session, an MCP client we did not
write. The point was to find what the self-authored corpus could not.

Two phases: passthrough, to test the framing and get the first honest latency
number; then enforcing, with a capability minted from the traffic phase 1
actually observed.

Workload: 72 `tools/call` across 11 distinct tools — `read_text_file`,
`read_multiple_files`, `write_file`, `edit_file`, `list_directory`,
`directory_tree`, `search_files`, `get_file_info`, `create_directory`,
`move_file`, `list_allowed_directories` — in one sustained session that read a
small Python project, wrote a parser, and created a test file. Captured on all
four streams (client→warden, warden→server, server→warden, warden→client) so
every claim below is checkable against bytes rather than against warden's own
account of itself.

## Phase 1 — passthrough

**Stdout discipline held exactly.** `cmp` reports client→warden identical to
warden→server, and server→warden identical to warden→client, byte for byte
across ~100 KB. Zero corruption, zero reordering, zero reserialization. This
was worth checking rather than assuming: the relay forwards received bytes
deliberately, because re-encoding a decoded message reorders object members and
would invalidate the very signatures the project exists to verify. The capture
confirms the discipline survives a real peer.

**The real server sends shapes the toy never did.** It issued two `roots/list`
*requests* — server-initiated, not responses. Both id namespaces start at 0
independently, so a server request id can collide with a client request id.
warden handles it: `responseKey` rejects any message carrying a `method`, so a
server request is never mistaken for a reply to a pending call, and `inspect`
rejects any message without one. Verified in both directions. A pass, but a
pass that only a real peer could have produced.

**One framing bug, and it was a full enforcement bypass.**

A `tools/call` wrapped in a one-element JSON-RPC batch array reached the
upstream server without ever being authorized. `inspect` unmarshals into a
struct; a top-level array fails that unmarshal, returns `nil`, and `nil` skips
the authorize block entirely. Three independent pieces of evidence:

- an enforcing warden with `_meta` stripped denied every *unwrapped* call with
  `-32001`, so enforcement was live;
- the same run produced 6 audit records for 7 `tools/call` probes — the batches
  were not merely permitted, they were invisible;
- a `tee` on the upstream side caught warden forwarding `[{...}]` to the server
  in full.

Not exploitable against this particular server — the modern TypeScript SDK
silently drops batches, since MCP removed them in 2025-06-18 — but a complete
bypass against any server that honours JSON-RPC 2.0 batching, which MCP
2025-03-26 required.

**Fixed, fail-closed, before phase 2 was reported.** Enforcing mode now refuses
a top-level array at a new `frame` stage, ahead of `inspect`, and answers with
`-32001` on a null id (JSON-RPC 2.0 §6: a rejected batch gets one error object;
warden never opened the array, so it has no element id to answer with). The
audit record names no tool, deliberately — warden refused the frame without
learning what the array held, and recording a guess would be a claim it did not
verify.

The array is refused rather than opened. Authorizing its elements individually
would require re-serializing them, which the byte-verbatim rule forbids for
signature reasons, and a batch reply is a single array that this relay's
per-id pending map cannot pair back to its elements. Passthrough is unchanged:
§3.1 makes M1 the one mode that does not shape traffic, and there is no
enforcement in it to bypass.

Re-verified against the real server after the fix: both batch probes refused at
`frame`, **zero** `tools/call` lines reached the server, and all three probes
audited. Regression tests cover both halves of the split
(`TestEnforcingRefusesBatch`, `TestPassthroughForwardsBatch`); full suite is 447
tests green under `-race`.

## Latency, against a peer that does real I/O

The project's previous overhead numbers came from an in-process toy server
answering in ~20 µs. This is the first measurement against a peer doing real
work.

| | p50 | p99 |
|---|---|---|
| Upstream alone (Node + disk) | 0.25–0.39 ms | — |
| warden overhead, passthrough | **24–33 µs** | **82–154 µs** |
| warden overhead, enforcing depth 1 | **0.515 ms** | **2.264 ms** |
| warden overhead, enforcing depth 2 | **1.831 ms** | **3.257 ms** |

Passthrough overhead is 3 alternating rounds, n=583 each, measured inside
warden. Client-observed end-to-end latency was 729 µs p50 direct against 639 µs
p50 through warden — through is *faster*, which is not a real speedup but the
honest statement that at ~30 µs the overhead sits below this peer's run-to-run
variance. Nearest-rank percentiles, no interpolation, per project convention.

Two things the toy hid. The tail is 2.5x worse than the in-process baseline's
55 µs, attributable to 13 KB responses the toy never produced. And enforcement
against a real workload cost 18x passthrough at depth 1 — for a reason worth
following, below.

## Phase 2 — enforcing

A root was minted and a chain derived authorizing exactly the 11 tools observed
in phase 1, with argument constraints written from the real values: paths as
`one_of` over the files that existed, `range` bounds on `head`/`tail`, `subset`
for `paths`, `wildcard` where §3.4 offered nothing better. The intent was to
permit the workload. It was then replayed unchanged.

**15 of 72 permitted. 57 denied.** No enforcement was loosened to improve that
number; the denials are the result.

| Cause | n | Correct? |
|---|---|---|
| Closed world: constrained argument absent (`tail` 24, `head` 13) | 37 | **False positive** |
| `one_of`: path created during the run, so not enumerable at mint | 18 | **False positive** |
| `subset`: `read_multiple_files(paths)` against the enumerated tree | 2 | **False positive** |

All 57 are legitimate work refused. That is the number `eval/METHOD.md` says
cannot be produced from inside a self-authored corpus, and it is the main
deliverable of this exercise.

A second run with a read-only token derived one level deeper denied 60, of
which **8 are correct**: `edit_file` ×4, `write_file` ×2, `create_directory`,
`move_file`, each refused at §7 step 6b because the derived token does not
carry the tool. Attenuation works. The other 52 are the same three false-
positive classes.

### The closed world bites the opposite way round

The prediction going in was that §3.3 would reject *optional arguments the
client sends*. It does — but that is not what broke the workload. What broke it
is the other half: **naming an argument makes it mandatory.** Constraining
`head` and `tail` with sane bounds is ordinary operator hygiene, and it denied
every call that simply did not pass them.

Confirmed as a pincer against the same server. With a capability naming only
`path`, `read_text_file(path)` is permitted and `read_text_file(path, head)` is
denied. Add `head` and `tail`, and `read_text_file(path)` is denied instead.
There is no third policy. **An optional argument cannot be expressed**: name
it and it is required, omit it and it is forbidden.

§3.3 knows — "There is no 'optional constraint' mechanism" — and defers the
case to "profiles or extension constraint types". The deferral does not work,
and that is written up as [NOTES 11](ref/NOTES.md): an extension constraint
type is a predicate over a presented value, and §7 step 6b denies on absence
before any predicate runs, so no conformant registration can express this.
§3.3's own remedial sentence is also inverted — omitting an argument from the
constraint map does not permit the invocation to omit it, it forbids the
invocation to carry it.

### What the vocabulary could not say

The other 20 false positives are one shape: every denied path was created
*during* the workload. §3.4's core nine have no prefix, glob, or pattern type,
so "anything under this project directory" had to be spelled as `one_of` over
the files that existed at mint time — and a capability cannot enumerate files
the work is about to create.

This is a gap in the *core* set, not a defect in the draft: §10.3 establishes a
Specification Required registry for extension constraint types, and §3.5.3's
worked example is `path_containment`, with a `root` member — precisely this
case. The draft anticipated it. What the real workload adds is the cost of
declining the extension and staying core-only, which is not obvious from the
text: enumerating the tree pushed the capability to 15214 bytes, and that is
where the 18x enforcement overhead came from. **An inexpressive vocabulary is
paid for in chain size, and chain size is paid for in latency.** That trade
belongs in a deployment guide.

Two smaller vocabulary notes, both also reachable by extension registration and
so not spec defects: there is no element-wise combinator lifting a constraint
over the members of an array (`all`/`any` compose over constraints on the same
value, not over elements), which is what `read_multiple_files(paths)` wants;
and nothing in Table 2 addresses object-valued arguments, so `edit_file(edits)`
— an array of `{oldText, newText}` — could only be left `wildcard`. The
argument that decides what an edit writes is the one the core vocabulary cannot
touch.

### Traces were sufficient

Every denial was diagnosed from the audit record alone, without reading warden's
source. Each names a stage, a normative citation, and a plain-language detail:

```
core: tool "read_text_file": constrained argument "tail" is absent from
the invocation          (§7 step 6b, §3.3 closed-world)
```

The distinction that mattered most in practice was between *"argument absent
from the invocation"* and *"argument not named in the constraint map"* — same
clause, opposite fixes, and the trace says which. SPEC contribution 3 tested by
a user rather than by an assertion: it holds.

## What changed in the repository

- `internal/proxy/proxy.go` — `isBatch`/`denyBatch`, and a fail-closed frame
  check ahead of `inspect`. The only behaviour change; it removes a bypass and
  weakens nothing.
- `internal/proxy/enforce_test.go` — regression tests for both modes.
- `docs/ref/NOTES.md` — entry 11.

## A correction

Three NOTES entries were drafted from the phase 2 results before the draft was
re-read closely: optional arguments, missing prefix type, and missing structural
constraints. Two were wrong to file. §10.3's extension registry and §3.5.3's
`path_containment` example mean the draft anticipated both vocabulary gaps and
provided a conformant route to filling them — they are findings about the core
set's reach and about deployment cost, which is what this report is for, and
they were withdrawn from NOTES. Re-reading also sharpened the one that
survived, from "the draft never addresses optional arguments" (false — it
addresses them explicitly) to "the draft addresses them and defers to a
mechanism that cannot carry the deferral" (true, and a real defect).
