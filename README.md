# warden

An enforcement point for delegated agent authority.

When one agent hands work to another, it usually hands over its credentials
too — the sub-agent gets everything the parent had, and the only thing standing
between a prompt injection and your filesystem is the sub-agent's judgement.
warden replaces that with a token: agent A derives a narrower token for agent B,
and every call B makes is checked against **B's** authority, not A's.

The token format is
[draft-niyikiza-oauth-attenuating-agent-tokens-01](docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt)
(AAT). warden is an MCP proxy that speaks it: it sits between an agent and its
tool server, verifies the delegation chain on every `tools/call`, and refuses
anything the chain does not authorize — citing the clause of the draft that
said no.

## See it

```
go run ./demo
```

Thirty seconds, no setup, nothing to install. It runs two toy agents and the
real proxy in one process, and prints a transcript:

1. **A derives a narrower token for B.** A can search three sources and fetch
   two hosts; B gets one source, a smaller result limit, and no fetching.
2. **B does its job.** Allowed, and the tool answers.
3. **B calls `delete_file`.** Denied — its token does not list that tool.
4. **B calls `search` with `limit: 40`.** Denied — A's token allowed 50, B's
   allows 5, and authority is read from the end of the chain.
5. **B asks the library for a token wider than its own.** Refused; nothing is
   signed.
6. **B forges that token and presents it anyway.** Denied at verification, on
   the same clause.

The last two are the point. Attenuation is not a policy warden applies to
delegation — it is the only shape a delegation chain can have and still verify.
There is no configuration that makes either come out differently.

Every citation in the transcript is read out of the audit record warden wrote.
The prose around them is the demo's; the clauses are warden's.

## Use it

`cmd/wardend` is the proxy. It speaks stdio MCP to a client on one side and
spawns the tool server on the other:

```
go run ./cmd/wardend -audit warden.jsonl -- npx @modelcontextprotocol/server-everything
```

The client presents its chain and a proof-of-possession JWT in the `_meta`
object of each `tools/call` (`dev.warden/chain`, `dev.warden/pop`,
`dev.warden/spec`). Everything else is relayed byte-for-byte. A call warden
cannot decide is a call warden refuses: there is no bearer fallback and no
unauthenticated path, and a proxy that cannot write its audit log stops
authorizing.

## What it does and does not do

The adversarial evaluation lives in `eval/` and runs with `go run ./eval`. The
last run, on a corpus of 54 attacks and 19 benign delegation scenarios:

| | |
|---|---|
| attacks blocked | 100% (54/54) |
| blocks citing the right clause | 100% (54/54) |
| benign scenarios wrongly denied | 0% (0/19) |
| enforcement cost, depth 3 | ~0.3 ms p50 added per call |

Read [`eval/METHOD.md`](eval/METHOD.md) before believing any of that. It says
what the corpus cannot reach, which attacks warden knowingly does not stop and
why, and that the corpus and the code share an author.

Not implemented: revocation, operator static policy, audience binding as a
requirement, and the `invocation_constraints` extension — a chain carrying that
member is rejected rather than ignored.

## Layout

| | |
|---|---|
| `cmd/wardend` | the proxy binary |
| `internal/aat` | the token format, §7 chain verification, §6 derivation |
| `internal/core` | invariants I1–I4 over domain types; stdlib only |
| `internal/proxy` | the MCP relay and the enforcement pipeline |
| `internal/audit` | the decision record |
| `eval` | the adversarial corpus and the measurement harness |
| `demo` | the transcript above |
| `docs` | SPEC, ARCHITECTURE, ROADMAP, ADRs, and the vendored draft |

`STATE.md` is the running project journal: what is decided, what is deferred,
and why.
