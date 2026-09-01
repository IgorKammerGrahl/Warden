# warden

An independent Go implementation of
[draft-niyikiza-oauth-attenuating-agent-tokens-01](docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt)
(Attenuating Authorization Tokens, AAT): a library for the token format, chain
verification and derivation, plus `wardend` — an enforcement point that sits
between an agent and an MCP server over stdio and decides every `tools/call`
against the delegation chain the client presents.

It is a personal project with one author. It is not a product, it has no users,
and no part of it has been reviewed by anyone else. It was written to find out
what the draft says by implementing it, and the most useful things in it are
probably the two documents that record what implementing it turned up:
[`docs/ref/NOTES.md`](docs/ref/NOTES.md), sixteen places where draft-01
underdetermines behaviour, and [`eval/METHOD.md`](eval/METHOD.md), what the
measurements below do and do not cover.

## What the token is for

When one agent hands work to another, it usually hands over its credentials
too — the sub-agent gets everything the parent had, and the only thing standing
between a prompt injection and your filesystem is the sub-agent's judgement. An
AAT replaces that with a chain: agent A derives a narrower token for agent B
offline, and every call B makes is checked against **B's** authority, not A's.
Attenuation is not a policy the enforcement point applies — it is the only shape
a chain can have and still verify.

warden speaks that format at the MCP layer: it verifies the chain on every
`tools/call` and refuses anything the chain does not authorize, citing the
clause of the draft that said no.

## See it

```
go run ./demo
```

Thirty seconds, no setup, nothing to install. It runs two toy agents, the real
proxy and a toy MCP server as goroutines in one process, and prints a
transcript:

1. **A derives a narrower token for B.** A can search three sources and fetch
   two hosts; B gets one source, a smaller result limit, and no fetching.
2. **B does its job.** Permitted, and the tool answers.
3. **B calls `delete_file`.** Denied — its token does not list that tool.
4. **B calls `search` with `limit: 40`.** Denied — A's token allowed 50, B's
   allows 5, and authority is read from the end of the chain.
5. **B asks the library for a token wider than its own.** Refused; nothing is
   signed.
6. **B forges that token and presents it anyway.** Denied at verification, on
   the same clause.

The last two are the pair the demo exists for. `Derive` refuses through
`core.CheckLink` — literally the function §7 step 4 runs at the enforcement
point — so asking produced no token and forging produced one no verifier
accepts, for the same stated reason.

Every citation in the transcript is read out of the audit record warden wrote.
The prose around them is the demo's; the clauses are warden's.

## Run everything

| | |
|---|---|
| tests | `go test ./...` — 466 tests, 13 packages, stdlib plus `pgregory.net/rapid` |
| demo | `go run ./demo` |
| adversarial evaluation | `go run ./eval` — builds `wardend`, presents both corpora to a live proxy, writes `eval/results/` |
| §4.5 interop comparison | `go run ./interop` — needs `cargo` on `PATH`; pulls and builds a Rust shim |
| the proxy | `go run ./cmd/wardend -trust-anchors anchors.json -audit warden.jsonl -- npx @modelcontextprotocol/server-everything` |

`shakedown2/` is the replay harness for the second real-peer shakedown. It is
run by hand against a live server from a captured stream, not from a single
command; its header comment has the invocation and
[`docs/SHAKEDOWN-2.md`](docs/SHAKEDOWN-2.md) has the results.

The client presents its chain and a proof-of-possession JWT in the `_meta`
object of each `tools/call` (`dev.warden/chain`, `dev.warden/pop`,
`dev.warden/spec`). Everything else is relayed byte-for-byte. A call warden
cannot decide is a call warden refuses: there is no bearer fallback and no
unauthenticated path, and a proxy that cannot write its audit log stops
authorizing.

## What is implemented

- **§7 chain verification**, all eight steps end to end: size and depth limits,
  cycle detection, root anchoring against a configured trust-anchor set,
  per-link signature and claim verification, capability projection, the §7 step
  6b invocation check, and proof of possession. Invariants I1–I6.
- **The nine §3.4 constraint types** with their `check` predicates, and the §4.5
  subsumption matrix as a table of the 19 permitted (parent, derived) pairs out
  of 81 — an allowlist, so a forgotten entry fails closed. `all` clause matching
  is Kuhn's bipartite matching, which §4.5 explicitly permits.
- **§6 derivation.** `aat.Deriver` mints child tokens, refusing through the same
  `core.CheckLink` the verifier runs, so a derivation that would die on arrival
  is never signed.
- **§5.2/§5.3 proof of possession**, required rather than optional: there is no
  path through `Verifier.Verify` that authorizes without it.
- **The wire primitives**: RFC 8785 JCS (used as a well-formedness gate, not
  only a serializer), RFC 7515 compact JWS restricted to EdDSA per RFC 8037,
  RFC 7638 thumbprints, RFC 9278 thumbprint URIs, §4.6 `par_hash` over the
  parent's JWS signing input.
- **The decision trace.** One JSONL audit record per decided call, carrying the
  verdict, the clause that produced it, the argument digest and the latency.
  §4.3/§4.4 limits are operator flags (`-max-delegation-depth`,
  `-max-token-lifetime`, `-audience`).

## What is not implemented

This list is not a roadmap. Each item is a thing warden does not do that a
reader might reasonably assume it does.

- **No stateful replay protection.** Only the §7 step 7g timestamp window —
  roughly 60 seconds at the default ±30 s tolerance. §8.5 says an enforcement
  point MUST implement stateful PoP `jti` tracking for irreversible or
  side-effecting invocations; warden does not, and could not apply the rule
  selectively even if it did, because nothing in a chain, a PoP or an invocation
  says which tools those are (NOTES 9).
- **No budget or rate controls, and no cumulative controls of any kind.** The
  reason they are absent is
  [ADR 0001](docs/adr/0001-invocation-granularity-constraints.md): AAT's
  extension registry is indexed by argument name and cannot host a control over
  a *sequence* of invocations. The mechanism proposed there is off by default
  and its counters are in-memory in one `wardend` process — a **declared
  non-goal**, not a deferred feature: nothing shares counters across instances.
- **No trust anchor rotation without restart.** `-trust-anchors` takes a set, so
  a rotation is a file edit, but applying it requires restarting the proxy.
  §8.9's "rotation without downtime" is not met and is not claimed (NOTES 10).
- **No revocation.** §8.9 puts per-token revocation outside the specification;
  `-max-token-lifetime` is the only instrument that exists, and shorter is the
  mitigation.
- **The transport binding is warden's, not the draft's.** The draft defines no
  MCP binding. `_meta["dev.warden/chain"]`, `dev.warden/pop` and
  `dev.warden/spec` are this project's invention; no other implementation reads
  them, and nothing about them is standardized or proposed for standardization.
- **Only `tools/call` can be decided.** In enforcing mode warden relays a fixed
  allow-list of MCP methods (`initialize`, `tools/list`, `*/list`, `ping`,
  notifications, responses to server-initiated requests) and refuses everything
  else at the frame. So **warden is unusable in front of a server whose primary
  interface is `resources/*` or `prompts/*`** — the AAT capability model has one
  noun and there is nothing to write in a token that would authorize a
  `resources/read` (NOTES 15). This was found by a real server publishing its
  whole graph through both a tool and a resource URI.
- **Optional arguments are inexpressible.** §3.3's closed world makes a
  constrained argument mandatory, so one capability cannot admit both call
  shapes of a tool with an optional argument. Against
  `@modelcontextprotocol/server-filesystem`, with a capability minted from the
  workload with the intent of permitting it, 37 of 72 calls were denied by this
  rule alone (NOTES 11).
- **No `invocation_constraints`, no HTTP/SSE transport, no policy file, no
  `wardenctl`.** A chain carrying an `invocation_constraints` member is
  *rejected*, not ignored — the behaviour ADR 0001 asks peers to have.

One more limit, which is about the evidence rather than the code: **no second
implementation of draft-01's token format exists.** `github.com/tenuo-ai/tenuo`
issues CBOR warrants over Ed25519 and implements none of §3.1, §3.2 or §5.2, so
warden's conformance to §6 and §7 is a claim about warden's reading, tested
against itself (NOTES 13). `interop/` compares §4.5 verdicts against tenuo's
constraint engine, which is a real second reader of the subsumption rules — and
that is the only layer where a second reader exists.

## The numbers, and what they are worth

`go run ./eval` presents an adversarial corpus and a benign corpus to a live
proxy and writes [`eval/results/summary.md`](eval/results/summary.md). The
committed run:

| | |
|---|---|
| adversarial cases blocked | 100% (61/61) |
| blocks citing the right clause | 100% (61/61) |
| benign delegation scenarios wrongly denied | 0% (0/19) |
| documented non-blocks | 4, counted out of the rate above and printed beside it |
| enforcement cost, depth 3 | 0.335 ms p50 / 1.115 ms p99 added per call |

**Read the block rate as a property of the corpus, not of warden.** The corpus
was written by the author of the code, from the author's own threat model. It
says every attack someone thought to write down was stopped; it says nothing
about the attacks nobody wrote.

That is not a hypothetical caveat, and there is a documented instance of exactly
what it misses. The first real client warden was pointed at — Claude Code in
front of `@modelcontextprotocol/server-filesystem` — got an unauthorized
`tools/call` through by wrapping it in a JSON-RPC batch array: the classifier
unmarshalled a top-level array into a struct, failed, returned `nil`, and `nil`
meant "relay it". The bypass sat underneath a 100% block rate because no case in
the corpus could express that message shape. A sibling audit then found five
more of the same class. All are now corpus cases; the class was invisible until
a peer nobody here wrote showed up. The second shakedown, against
`@modelcontextprotocol/server-memory`, found the `resources/read` bypass in the
list above, by the same mechanism.

The latency figures are against an in-process test server answering in tens of
microseconds. The microseconds transfer to a real peer; any ratio computed from
them does not. Enforcement cost tracks chain *size*, not call count: against a
real server, a 16,556-byte capability cost 1.965 ms p50 where a
1,240-byte one cost 0.271 ms.

[`eval/METHOD.md`](eval/METHOD.md) is the whole of the method and its limits —
including that the benign corpus structurally cannot exercise I1–I4, that
audience binding is unexercised, and that 19 hand-written benign cases will not
find a false positive needing an unusual argument shape. Read it before quoting
a figure.

## Findings about the draft

[`docs/ref/NOTES.md`](docs/ref/NOTES.md) records fourteen places where draft-01
underdetermines behaviour or where a stated mechanism does not reach what it is
pointed at, each with what the text says, what it leaves open, what warden does
and why, and whether it is worth raising. Entry status is marked in that file's
header; two entries have been accepted by the draft author for -02.

[ADR 0001](docs/adr/0001-invocation-granularity-constraints.md) is the longest
single finding: AAT's extension model admits only argument-granularity
constraints, cumulative controls are invocation-granularity, and the draft has
no extension point at that granularity — nor any extension point whose absence
of support a peer can detect. It proposes a mechanism and a fallback.

[`docs/SHAKEDOWN.md`](docs/SHAKEDOWN.md) and
[`docs/SHAKEDOWN-2.md`](docs/SHAKEDOWN-2.md) are the two runs against real MCP
servers driven by a real client, which is where the enforcement-side findings
came from.

## Layout

| | |
|---|---|
| `cmd/wardend` | the proxy binary |
| `internal/aat` | the token format, §7 chain verification, §6 derivation, PoP |
| `internal/aat/jcs`, `internal/aat/jws` | RFC 8785 and RFC 7515/8037 |
| `internal/core` | §3.4 constraints, §3.3 capabilities, §4.5 subsumption, I1–I4; stdlib only |
| `internal/proxy` | the MCP relay and the §3.2 enforcement pipeline |
| `internal/audit` | the decision record |
| `eval` | the adversarial and benign corpora, the harness, `METHOD.md` |
| `interop` | the §4.5 verdict comparison against tenuo |
| `demo` | the transcript above |
| `shakedown2` | the phase-2 replay harness for the second shakedown |
| `docs` | SPEC, ARCHITECTURE, ROADMAP, the ADR, the shakedowns, and the vendored draft |

`STATE.md` is the running project journal: what is decided, what is deferred,
and why. It is written for the next session rather than for a reader, and it is
long.

## License

Apache-2.0 ([`LICENSE`](LICENSE)). Chosen over MIT for its explicit patent grant
(§3): this is an implementation of a standards-track draft, and an
implementation that a working group might look at should not make anyone think
about patents before reading it.

`docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` is not covered by
that license. It is an IETF Internet-Draft, redistributed in full under the IETF
Trust's provisions; see [`docs/ref/README.md`](docs/ref/README.md) for its
provenance.
