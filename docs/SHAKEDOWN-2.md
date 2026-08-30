# Real-peer shakedown 2 — a server with a different shape

Shakedown 1 ran warden in front of `@modelcontextprotocol/server-filesystem`
and found six enforcement bypasses that 54 adversarial cases had not, because
the value was in the message shapes a real server and a real client produce
that a self-authored corpus never does. This repeats it against a server
chosen to be unlike the first one, and follows the method in
[SHAKEDOWN.md](SHAKEDOWN.md) without re-deriving it.

## Why this server

`@modelcontextprotocol/server-memory` 2026.7.4 — a knowledge graph over a JSON
file — for three reasons decided before any traffic was captured.

1. **Every mutating tool takes an array of objects.** `create_entities` takes
   `entities: [{name, entityType, observations[]}]`; `create_relations` takes
   `relations: [{from, to, relationType}]`; and so on for four more. The field
   that decides what gets written is nested three levels inside the single
   argument. §3.4's Table 2 has no type for an object, so this is the
   vocabulary's blind spot by construction rather than by accident.
2. **`read_graph` takes no arguments at all** — its `inputSchema` is
   `"properties": {}`. §3.3's closed world is a rule about the relationship
   between an argument map and a constraint map, and it had never been tested
   against a tool whose argument map is always empty.
3. **It is stateful and self-referential.** Entity names created in call *n*
   are arguments to call *n+k*, so a capability minted from the state at *t=0*
   is provably incomplete by *t=1*. Shakedown 1 found that class as a
   coincidence; here it is guaranteed.

The workload came from two headless Claude Code sessions told to build and
exercise a graph about warden itself, in many small calls: **71 `tools/call`
across all nine tools**, plus the handshake.

## Phase 1 — passthrough

```
client → warden   79 lines   26047 B
warden → server   79 lines   26047 B   cmp: identical
server → warden   77 lines  178896 B
warden → client   77 lines  178896 B   cmp: identical
audit records     71         (one per tools/call, decision "passthrough")
```

Byte-identical in both directions across ~200 KB. Zero corruption, zero
reordering, zero re-serialization — the property signatures depend on.

Client methods: `initialize` ×2, `notifications/initialized` ×2, `tools/list`
×2, `resources/list` ×2, `tools/call` ×71. Server-initiated requests: **zero**.

### Shapes the framing had not seen

- **`resources/list`.** This server declares a `resources` capability, which
  the filesystem server does not, so the client asks for the list. First
  non-`tools` MCP noun to cross the proxy in either shakedown. It is where the
  finding below started.
- **`"arguments": {}`.** Four `read_graph` calls, an empty argument object for
  a tool that declares no properties. Relayed correctly; §3.3's closed world
  is satisfied vacuously by an empty constraint map, and it is worth having
  seen the pair once.
- **No server-initiated requests at all.** The filesystem server sends
  `roots/list` and warden has to relay a client *response* — a message with no
  `method`. This server never does. The absence is a shape too: it means the
  no-method path is exercised by exactly one of the two real peers we have
  tested, which is now recorded in a regression test rather than in luck.
- **`protocolVersion` 2025-11-25** negotiated by both ends, two revisions
  ahead of the last one warden was watched against.

Nothing here broke the framing.

## The finding: a message that reached the upstream without a decision

The brief's instrument was the count check — audit records against
`tools/call` lines reaching the upstream — and the shape it surfaced is not a
malformed message. It is an ordinary, well-formed one.

This server publishes its knowledge graph **twice**: through the `read_graph`
tool, and as the resource `memory://knowledge-graph`, described in its own
`resources/list` response as "The full knowledge graph with all entities and
relations".

Under a leaf capability authorizing exactly one tool and one query
(`search_nodes`, `one_of ["Ed25519"]`), in a single run:

```
read_graph                                  denied 6×  @verify §7 step 6b
resources/read memory://knowledge-graph     11805 B of graph returned

lines reaching upstream            14
lines with an audit record          6
audit records mentioning resources  0
```

Eight messages reached the upstream with no authorization decision and no
audit record, and one of them returned the entire dataset that `read_graph`
was being denied for in the same run. Every signature verified, every
constraint intact, every one of them irrelevant.

**Why it happened.** `inspect` classifies a client message and returns
`(nil, true)` for "classified, and it is not a `tools/call`". The caller reads
`true` as permission to relay. That conflates *warden understood this message*
with *warden may forward this message*, and they are not the same claim: §3.3
capabilities describe tools and only tools, so for any other method there is
no capability to check against and forwarding is an unconditional grant of
whatever that method reaches.

This is the same class as shakedown 1's batch bypass — a shape the proxy could
not authorize was forwarded anyway — arriving through a door the generalized
rule did not cover, because the rule was written about *framing* and this
message frames perfectly.

**The fix.** In enforcing mode, `tools/call` is decided and every other method
is refused at the frame, except an allow-list of methods that carry no
server-held content: `initialize`, `notifications/initialized`,
`notifications/cancelled`, `ping`, `tools/list`, `resources/list`,
`resources/templates/list`, `prompts/list`, and responses to server-initiated
requests (no `method`, a `result` or an `error`). An allow-list rather than a
list of dangerous methods, for the same reason as last time: the bypass was a
method nobody had listed.

The refusal is answered on the message's own id, not on null. A null id is the
honest answer when the id is one of the things warden could not read; here
warden read the method and the id perfectly well and is refusing, not failing
to parse.

After the fix, same run:

```
lines reaching upstream            13
lines with an audit record          6
relayed without a decision          7   (initialize, notifications/initialized,
                                         tools/list ×3, resources/list ×2)
resources/read                     denied @frame ARCHITECTURE §3.2, on id 9001
```

**What it costs.** Warden is now unusable in front of a server whose primary
interface is resources or prompts, and correctly so — there is nothing an
issuer could write in an AAT that would authorize `resources/read` for one
uri. That is [NOTES 15](ref/NOTES.md), and it is a gap in the draft, not a
gap in the implementation.

## Probes: fourteen shapes, two families

The framing family asks whether a message can reach the upstream without a
decision. The parser-agreement family asks something sharper: warden
classifies with `encoding/json` and this upstream parses with V8, and every
duplicate JSON member is a place the two could disagree. A disagreement is a
full bypass, because the PoP is signed over the tool name and arguments
*warden* read. Each probe carries a valid binding, so it reaches a real
decision instead of dying at `bind`.

| probe | result | decided? |
|---|---|---|
| `resources/read` | deny @frame §3.2 | yes *(was the bypass)* |
| `resources/list` | relayed | no — allow-list |
| `tools/call` in a 1-element batch | deny @frame §3.2 | yes |
| `params` is an array | deny @frame §3.2 | yes |
| `tools/call` with no `params` | deny @bind §3.1 | yes |
| `arguments` is an array | deny @bind §3.1 | yes |
| two JSON values on one line | both classified and decided independently | yes |
| dup `method`: call, then list | warden read `tools/list`; upstream answered `tools/list` | relayed |
| dup `method`: list, then call | warden read `tools/call`, permitted; upstream ran it | yes |
| dup `name`: `read_graph`, then `search_nodes` | warden permitted `search_nodes`; upstream returned the 690 B search result, **not** the 11805 B graph | yes |
| dup `name`: `search_nodes`, then `read_graph` | deny @verify §7 step 6b | yes |
| dup `arguments` | deny @verify §3.4 `one_of` | yes |
| method spelled `"\u0074ools/call"` | decoded to `tools/call`, enforced, permitted, forwarded verbatim | yes |
| `tools/call` sent as a notification | decided and audited; never forwarded | yes |

**`encoding/json` and V8 agree on every duplicate-member shape tested.** Both
are last-wins, and the sharpest case proves it from the server's side rather
than from the parsers': in the `read_graph`-then-`search_nodes` probe, warden
authorized and signed for `search_nodes`, and a first-wins upstream would have
returned the whole graph. It returned 690 bytes. This is a negative result
about two specific parsers, not a general one — a Python or a Ruby upstream is
untested, and the shape stays in the probe set for the next peer.

The two-values-on-one-line probe matters for a different reason: warden's
decoder is a stream, not a line reader, so a client that packs two messages
into one write gets two independent decisions rather than one decision and one
free ride.

## The closed world against object-valued arguments

The brief asked what `exact`-on-a-whole-object costs. The first thing it cost
was the premise: **`exact` cannot take an object.** Table 2 restricts it to
"value (any scalar)", and warden enforces that. The routes that remain are
`one_of` over whole argument values, and `subset` over array *elements* — both
of which Table 2 permits only by silence, since neither row says what its
members may be.

All five profiles were replayed against the same 71 calls, from the same
graph snapshot, at chain depth 1:

| profile | what it says about object arguments | chain | permitted | denied |
|---|---|---|---|---|
| `wildcard` | nothing (control) | 1240 B | 71 | 0 |
| `readonly` | three read tools, no writes | 1404 B | 27 | 44 |
| `observed` | `wildcard` on objects, `one_of`/`subset` on the strings | 2427 B | 68 | 3 |
| `subsetobj` | `subset` over the 122 observed elements | 16363 B | 71 | 0 |
| `exactobj` | `one_of` over the 64 observed whole values | 16556 B | 71 | 0 |

**The result is the inverse of shakedown 1.** There, 57 of 72 calls were
denied and the policy was too tight. Here the honest operator attempt
(`observed`) permits 68 of 71 — and permits them not because anything was
validated but because six of nine tools got `wildcard` on their only argument.
The policy is not too tight. It is **vacuous**: an attacker with that leaf may
write any entity, any relation, any observation, any content, to the graph.
Nothing in the chain is checked, and nothing in the chain could be.

The two expressive profiles do constrain, and they cost 13× the chain to
permit exactly the same 71 calls. They are not policies. They are the
recording, notarized. `subsetobj` is the better of the two — it constrains each
object independently, so it permits recombinations the recording never
contained, where `exactobj` permits the recorded calls and nothing else — and
the entire difference between a constraint and a transcript rests on a
sentence the draft did not write. That is [NOTES 16](ref/NOTES.md).

## Every denial, and whether it was correct

Across all profiles, **three false positives**, and they are the same class
shakedown 1 found.

| profile | n | cause | correct? |
|---|---|---|---|
| `observed` | 3 | `delete_entities` @§3.4 `subset` | **false positive** |
| `readonly` | 44 | six write tools @§7 step 6b | correct |
| `searchonly` | 57 | eight unauthorized tools @§7 step 6b | correct |
| `searchonly` | 12 | `search_nodes` @§3.4 `one_of` | correct |
| `wildcard`, `subsetobj`, `exactobj` | 0 | — | — |

The three false positives are entity names the workload **created during the
run** and then deleted. The capability was minted from the graph as it existed
at *t=0*, which is the only state an issuer can enumerate, and §3.3's closed
world denies what the issuer did not name. Identical in shape to shakedown 1's
`one_of` over paths created during the run, and it is inherent: a stateful
server's argument space is a function of its own history.

`readonly` is worth stating separately because it is clean in both directions:
all 44 write calls denied, all 27 read calls permitted, zero false positives.
The vocabulary works at tool granularity. It is argument granularity over
objects where it has nothing to say.

## Latency, against a peer that does real I/O

`overhead = total − upstream`, nearest-rank percentiles, n = 71 per row. The
upstream is a Node process reading and writing a JSON file, so the upstream
column is a real number rather than the tens of microseconds eval's in-process
server reports.

| configuration | depth | chain | overhead p50 | overhead p99 | upstream p50 |
|---|---|---|---|---|---|
| passthrough (real client) | — | — | 0.132 ms | 0.529 ms | 1.964 ms |
| enforcing `wildcard` | 1 | 1240 B | 0.271 ms | 0.769 ms | 0.494 ms |
| enforcing `readonly` | 1 | 1404 B | 0.271 ms | 1.286 ms | 0.478 ms |
| enforcing `observed` | 1 | 2427 B | 0.322 ms | 0.850 ms | 0.454 ms |
| enforcing `subsetobj` | 1 | 16363 B | 0.925 ms | 2.050 ms | 0.591 ms |
| enforcing `exactobj` | 1 | 16556 B | 1.965 ms | 4.931 ms | 1.061 ms |
| enforcing `wildcard` | 2 | 2626 B | 0.411 ms | 1.471 ms | 0.474 ms |
| enforcing `readonly` | 2 | 2954 B | 0.415 ms | 1.438 ms | 0.606 ms |
| enforcing `observed` | 2 | 4999 B | 1.025 ms | 2.163 ms | 0.800 ms |
| enforcing `subsetobj` | 2 | 32871 B | 4.544 ms | 5.887 ms | 1.028 ms |
| enforcing `exactobj` | 2 | 33258 B | 4.586 ms | 9.481 ms | 1.197 ms |

Passthrough overhead against a real client and a real server is **0.132 ms
p50**, and the peer's own work is fifteen times that.

Enforcement tracks chain size, not call count — the same 71 calls cost 0.271 ms
under a 1240-byte chain and 1.965 ms under a 16556-byte one. Shakedown 1
predicted this in a sentence ("expressiveness is paid for in chain size, and
chain size is paid for in latency"); here it is measured against the case where
the vocabulary *forces* the issuer to inline the data. At depth 2 with an
object whitelist, warden costs four times what the server costs. An operator
who wants object-level constraints under draft-01 is buying them at that price,
and getting a transcript for the money.

## What changed in the repository

- `internal/proxy/proxy.go` — `relayed`, the enforcing-mode method allow-list;
  `inspect` returns `known=false` for anything else; `denyUnclassified` names
  the refused method and answers on its own id. Removes a bypass, weakens
  nothing.
- `internal/proxy/enforce_test.go` — `TestEnforcingRefusesUnauthorizableMethod`,
  eleven cases across refused methods, relayed methods, and the no-method
  response the filesystem server produces.
- `eval/adversarial.go` — two T1 cases: `frame-resources-read` and
  `frame-method-outside-the-vocabulary`. Corpus is 61 deny cases, still 100%
  blocked and 100% correctly attributed.
- `docs/ref/NOTES.md` — entries 15 and 16.
- `shakedown2/` — the replay harness, capability profiles, and the values
  generated from the phase-1 capture. Committed because "mechanical and
  reproducible" is worth more than one fewer directory; shakedown 1's harness
  was not kept and re-deriving it cost most of this session's setup.

## Limits of this pass

- Two peers is not a sample. Both servers are TypeScript on Node, so the
  parser-agreement result is about `encoding/json` versus V8 and says nothing
  about a Python or Ruby upstream.
- The workload came from a Claude Code session told to exercise the graph. It
  is real client traffic, not adversarial traffic; the probes are the
  adversarial part and they were written by the same author as the code, which
  is the standing caveat from `eval/METHOD.md`.
- The `resources/read` finding was found by the count check, which is a
  *counting* instrument. It surfaces messages that reach the upstream without a
  record. It cannot surface a message that is decided incorrectly, and nothing
  in this pass tested that.
- Latency rows are single runs of 71 calls on a loaded developer machine, not
  alternating rounds. The ordering between profiles is far larger than the
  noise; the absolute p99s are not to be quoted.
