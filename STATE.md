# warden — STATE

Updated: 2026-08-23 (M2 closed)

This file is the cold-start handoff. A session that has read this and
`docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` should be able
to start M3 without re-exploring the repo.

## Current position

**M0a, M0b1, M0b2, M1 and M2 are complete.** M3 has not started.

M0a was encoding and crypto only: a token's own claims, its own signature, its
own shape. M0b1 added `internal/core` — the nine §3.4 constraint types with
`check`, the §4.5 `subsumes` matrix, the §3.5.1 soundness property — all of it
single-constraint and single-pair.

M0b2 added chains, and it is the milestone that made the previous two do
something. `core` gained the §3.3 capability structure, the §7 step 6b
invocation check, and the domain invariants I1–I4 over a domain-typed token.
`aat` gained `Verifier`, which runs the §7 eight-step algorithm end to end:
size check, cycle detection, root anchoring, per-link verification, capability
projection, invocation authorization, PoP. `core.Subsumes` finally has a
caller — §7 step 4p4.

M1 added the first code above the library: `wardend`, an MCP stdio proxy that
relays JSON-RPC between a client and one upstream server and writes an audit
record per `tools/call`. It calls nothing in `internal/core` and nothing in
`internal/aat` except the JCS canonicalizer, and that only to digest arguments.

M2 connected the two. `wardend` now denies: every `tools/call` runs the §3.2
pipeline, an unbound or out-of-authority call comes back to the client as a
JSON-RPC error citing the clause that refused it, and the same citation is in
the audit record. `-passthrough-only` keeps M1's unenforced path alive on the
same binary, which is what makes the overhead figure a measurement rather than
a comparison of two builds.

**warden enforces the stateless half of the draft.** What does not exist: no
`invocation_constraints`, no budget or rate counters, no PoP `jti` replay set,
no revocation, no policy file, no key rotation, no HTTP/SSE transport, no
`wardenctl audit tail`, no interop test against another implementation. Every
one of those is state, configuration or transport rather than a hole in the
verification algorithm — the §7 path is complete and enforced.

---

## Repository layout

```
docs/SPEC.md, ARCHITECTURE.md, ROADMAP.md   Phase 1 design (rev. 3)
docs/adr/0001-*.md                          invocation-granularity constraints
docs/ref/draft-...-01.txt                   vendored AAT draft-01
docs/ref/NOTES.md                           spec ambiguities found while implementing
internal/aat/jcs/                            RFC 8785 JSON canonicalization
internal/aat/jws/                            RFC 7515 compact serialization, Ed25519 only
internal/aat/                                AAT claim set, JWK/thumbprints, PoP JWT
internal/core/                               domain: §3.4 constraints, §3.3 capabilities, I1-I4
internal/audit/                              the ARCHITECTURE §6 decision record, JSONL, latency stats
internal/aat/aattest/                        shared chain fixture: one chain, minted the same way for every test
internal/proxy/                              the relay (framing, correlation) and the §3.2 enforcement pipeline
internal/testserver/                         ~100-line stdio MCP server, the e2e's upstream peer
cmd/wardend/                                 the daemon: flags, subprocess, wiring, latency report
```

**All section citations (§x.y) resolve against the vendored draft**, never
against quotations copied into our own docs. That rule exists because ADR 0001
was written against a quotation and acquired four errors; see Open decisions.

### What each package owns

**`internal/aat/jcs`** — RFC 8785. One exported function. Owns: UTF-16
code-unit property sorting, ECMAScript `Number::toString` serialization
(ECMA-262 §7.1.12.1), the minimal escape set, lone-surrogate and invalid-UTF-8
rejection, duplicate-member rejection, a 1000-deep nesting cap, trailing-data
rejection. Used by `jws` and `aat` as the uniqueness/well-formedness gate, not
only as a serializer — several callers discard the output and keep the error.

**`internal/aat/jws`** — RFC 7515 compact serialization restricted to EdDSA
(RFC 8037). Owns: the §8.13 algorithm allowlist (a one-entry map, so the
package cannot be confused into another algorithm), `alg:"none"` and absent-alg
rejection, `crit` rejection, canonical-base64url enforcement per segment, and
retention of the exact signing input. Knows nothing about AAT claims.

**`internal/aat`** — draft §3.2 claim set, RFC 7638 thumbprint + RFC 9278
thumbprint URI, §4.6 `par_hash`, §5.2 PoP JWT, §7 steps 3a/4a/7a algorithm/key
consistency, §7 steps 3l/4b2 private-key-material rejection, §4.3.1
`MAX_TOKEN_SIZE`. Since M0b2 it also owns the **§7 step sequence**
(`Verifier`), I5 cryptographic linkage (`par_hash` over the parent's signing
input), I6 proof of possession, and §4.3.1 `MAX_STACK_SIZE`. It knows no
constraint semantics: every domain invariant is a call into `core`.

**`internal/core`** — the domain layer, stdlib-only, no wire format. Owns the
§3.4 argument-constraint vocabulary (nine types, `Check`), the §4.5 subsumption
matrix (`Subsumes`), §3.4 `MAX_CONSTRAINT_DEPTH`, and — since M0b2 — the §3.3
capability structure (`Capabilities`, `ConstraintMap`), the §7 step 6b
invocation check, and the domain invariants I1–I4 over a domain-typed `Token`.
Knows nothing about JWTs, base64, or signatures. `ParseCapabilities` takes the
already-decoded `authorization_details` array elements as raw JSON — the outer
JWT is `aat`'s problem, the entries' meaning is `core`'s.

The **subsumption matrix is a table of PERMITTED (parent type, derived type)
pairs**, 19 of the 81 core pairs. There is no default branch and no list of
rejects: §4.5's closing sentence is a default-deny rule, and the only way to
implement default-deny so that a *forgotten* entry fails closed is for the
permission to be the thing that must be written down. `TestAllCorePairs`
asserts all 81; `TestPermittedTableMatchesDraft` pins the table's key set
against §4.5 read independently, so the 81-pair test is not a tautology.

Three rules where the natural implementation is wrong, all covered by named
tests: **wildcard is asymmetric** (a derived wildcard is valid only against a
parent wildcard; everything else subsumes a parent wildcard), **derived
`not_one_of` against a parent `one_of` is invalid** and looks plausible, and
**range inclusivity matters only at an equal bound** (derived exclusive against
parent inclusive is tighter; the reverse admits the endpoint).

`all` clause matching is **Kuhn's augmenting-path bipartite matching**, not the
literal backtracking pseudocode. Same relation, same answers — does a matching
saturating the parent clauses exist — in O(V·E) rather than O(n!); §4.5
explicitly permits "Hopcroft-Karp or similar maximum matching algorithms". The
pseudocode's O(n!) is reachable by an attacker, since clause count is bounded
only by `MAX_TOKEN_SIZE`, not by `MAX_CONSTRAINT_DEPTH`. Greedy matching is
what §4.5 warns against and this is not greedy: `augment` displaces an earlier
assignment when a later parent clause has no other candidate.

### Public API of `internal/aat` (signatures only)

```go
const  DefaultMaxTokenSize = 65536                                    // §4.3.1 RECOMMENDED
const  ThumbprintURIPrefix = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
var    MaxTokenSize        = DefaultMaxTokenSize                      // operator config, set once at startup

type Claims struct{ JTI, Issuer string; IssuedAt, Expires int64; Confirmation Confirmation;
                    DelegationDepth, MaxDelegationDepth int; ParentHash string;
                    AuthorizationDetails []json.RawMessage }
type Confirmation struct{ JWK *JWK }
type JWK struct{ Kty, Crv, X, D string }
type PoPClaims struct{ JTI string; IssuedAt int64; TokenID, Tool, Audience string; Args map[string]any }
type Token struct{ Claims Claims; ... }
type PoP   struct{ Claims PoPClaims; ... }

func NewJWK(pub ed25519.PublicKey) *JWK
func (j *JWK) PublicKey() (ed25519.PublicKey, error)
func (j *JWK) Thumbprint() (string, error)
func (j *JWK) ThumbprintURI() (string, error)

func Mint(c Claims, key ed25519.PrivateKey) (*Token, error)
func Parse(compact string) (*Token, error)
func (t *Token) Verify(key *JWK) error
func (t *Token) Compact() string
func (t *Token) Payload() []byte
func (t *Token) SigningInput() []byte
func ParentHash(parent *Token) string

func SignPoP(c PoPClaims, key ed25519.PrivateKey) (string, error)
func ParsePoP(compact string) (*PoP, error)
func (p *PoP) Verify(key *JWK) error
func (p *PoP) Compact() string
func (p *PoP) Payload() []byte
func (p *PoP) SigningInput() []byte
```

Added by M0b2 — the §7 orchestrator:

```go
const DefaultMaxStackSize = 262144   // §4.3.1 RECOMMENDED MAX_STACK_SIZE
const DefaultPoPSkew      = 30       // §5.3 RECOMMENDED PoP clock tolerance, seconds
var   MaxStackSize        = DefaultMaxStackSize   // operator config, set once at startup

type Verifier struct {
        TrustAnchors []*JWK        // §7 step 3b; empty means nothing verifies
        Limits       core.Limits   // §4.3/§4.4 bounds; the zero value is rejected
        PoPSkew      int64         // seconds; 0 is rejected, use DefaultPoPSkew
        Audience     string        // non-empty => §7 step 7d aat_aud binding is required
        Now          func() int64  // nil = time.Now, for tests
}

func (v *Verifier) Verify(chain []string, tool string, args map[string]any, popJWT string) error
```

`Verify` is the whole of §7: `chain[0]` is the root, `chain[len-1]` the leaf,
and a nil return is step 8 PERMIT. It returns one error naming the step and
invariant that denied — the errors are for operators reading an audit log, not
for a remote peer.

Four things a caller must know before using this:

1. **`Parse` does not verify.** A `*Token` from `Parse` is structurally valid
   and cryptographically unattested. §7 step 2c requires reading `jti` from an
   unverified payload, so `Parse` runs on attacker-controlled bytes by design.
2. **`Verify` is single-token.** Signature plus algorithm/key consistency. It
   does not walk a chain, check I1–I5, or evaluate constraints. *Choosing* the
   key is `Verifier`'s job: a trust anchor for the root, the parent's
   `cnf.jwk` for every other token.
3. **`Verify` takes a `*JWK`, not an `ed25519.PublicKey`.** That is what makes
   the §7 alg↔`kty`/`crv` check representable at all — a raw Ed25519 key cannot
   express the mismatch the check exists to catch. The check runs *before*
   signature verification, per §7's "regardless of whether the signature bytes
   would verify under an alternate interpretation".
4. **Unrecognized claims are ignored and not preserved.** A `Token` is never
   re-serialized; `Payload()`/`SigningInput()` return the bytes that were
   actually signed. A future `invocation_constraints` reader takes them there.

### Public API of `internal/core` (signatures only)

```go
const MaxConstraintDepth = 32                     // §3.4 RECOMMENDED, a constant not operator config
const TypeExact, TypeRange, TypeOneOf, TypeNotOneOf, TypeContains,
      TypeSubset, TypeWildcard, TypeAll, TypeAny = ...   // §3.4 Table 2
var   CoreTypes []string                          // Table 2 in table order

type Constraint struct{ Type string; Value any; Min, Max *float64;
                        MinInclusive, MaxInclusive bool;
                        Values, Excluded, Required, Allowed []any;
                        Clauses []Constraint }

func ParseConstraint(raw []byte) (*Constraint, error)
func (c *Constraint) Check(v any) bool            // §3.4 check predicate
func Subsumes(derived, parent *Constraint) bool   // §4.5, sound and conservative
```

Added by M0b2 — capabilities and the domain invariants:

```go
const CapabilityType = "attenuating_agent_token"   // §3.3

type ConstraintMap map[string]*Constraint          // argument name -> constraint
type Capabilities  struct{ Tools map[string]ConstraintMap }

func ParseCapabilities(details []json.RawMessage) (*Capabilities, error)  // §3.3
func CheckI4(child, parent *Capabilities) error                           // §7 step 4p
func (c *Capabilities) CheckInvocation(tool string, args map[string]any) error  // §7 step 6b

type Token struct{ JTI, Issuer string; IssuedAt, Expires int64;
                   Depth, MaxDepth int; HolderKeyURI string; Caps *Capabilities }
type Limits struct{ MaxDelegationDepth int; MaxIATSkew, MaxTokenLifetime int64 }
var  DefaultLimits = Limits{MaxDelegationDepth: 8, MaxIATSkew: 30, MaxTokenLifetime: 7776000}

func CheckRoot(root *Token, now int64, lim Limits) error           // §7 steps 3c, 3e-3k, 3m
func CheckLink(parent, child *Token, now int64, lim Limits) error  // §7 steps 4c-4p, I1-I4
```

Four more things a caller must know:

4. **A nil `*Capabilities` is the empty capability set, not an error.** §7 step
   4n defines a token with no `attenuating_agent_token` entry as one with an
   empty `tools` map, and the methods are nil-safe so that definition lives in
   one place instead of at every call site. A non-leaf derived token MAY carry
   zero entries; §3.3 requires exactly one in a root and in a leaf, and
   `Verifier` enforces the leaf half because leaf-ness is only knowable there.
5. **`Token.HolderKeyURI` is computed by the wire layer**, not stored in the
   token. It is `jwk_thumbprint_uri(cnf.jwk)` of *that* token, and I1 is the
   one-line check `child.Issuer == parent.HolderKeyURI`. Putting the URI in the
   projection is what keeps thumbprinting — base64, SHA-256, JSON — out of
   `core`.
6. **`Limits` has no usable zero value.** `MaxDelegationDepth: 0` would deny
   every chain and `MaxIATSkew: 0` would deny every clock, so `check` rejects
   the zero value rather than silently enforcing it. `DefaultLimits` is a
   deployment default, not a draft-mandated one: Appendix B.4 declines to
   recommend a `MAX_DELEGATION_DEPTH`, so 8 is ours.
7. **`CheckI4` is not `Subsumes` lifted over maps.** Three of its four rules
   are about *key sets*, not constraints: 4p1 tool subset, 4p2 exact key-set
   equality when the parent map is non-empty, 4p3 any key set when it is empty.
   Only 4p4 calls `Subsumes`. See the M0b2 trap note below.

Three things a caller must know:

1. **`Subsumes` is sound, not complete.** True means: for every argument value
   v, `derived.Check(v)` implies `parent.Check(v)`. False means only that the
   procedure could not establish that — §3.5.1 property 2 explicitly permits
   returning false for semantically subsuming pairs. Returning true for a
   non-subsuming pair is the one outcome that breaks attenuation, and is the
   only thing the property test asserts.
2. **`ParseConstraint` does not detect duplicate members.** Constraints arrive
   inside an AAT payload that `internal/aat` has already put through the JCS
   gate, and JCS rejects duplicates. A caller feeding it bytes from anywhere
   else must run that gate itself; `core` does not import the wire layer.
3. **`Check` takes `encoding/json` output** — `float64`, `[]any`,
   `map[string]any`, `nil`. `1` and `1.0` are the same argument value, the same
   identification RFC 8785 makes upstream.

---

## M2 exit state

`wardend` runs the ARCHITECTURE §3.2 pipeline on every `tools/call` and
authorizes nothing without a chain. `go test ./... -race` is green across nine
packages; `go vet` and `gofmt -l` are clean.

### The pipeline, and the one ordering that matters

`(*Enforcer).Decide` in `internal/proxy/enforce.go`. Five stages, first failure
short-circuits, every stage appends a trace step carrying its own `ref`:

1. **bind** — ARCHITECTURE §3.1. `_meta` must carry all three of
   `dev.warden/chain`, `dev.warden/pop`, `dev.warden/spec`; the chain must be a
   non-empty JSON array of non-empty strings, the PoP a non-empty JSON string,
   and the spec an **exact** match for `proxy.SpecVersion`. Then the number
   guard (below), then the arguments decode.
2. **verify** — §7 steps 1-5, one `aat.Verifier.Verify` call.
3. **capability** — §7 step 6, the closed-world invocation check.
4. **pop** — §7 step 7.
5. **extensions** — §2.4 / ADR 0001: a chain carrying `invocation_constraints`
   is rejected, never ignored.

Stages 2-4 are one call into `aat` because §5.3 requires that order and the
verifier already implements it. **A valid PoP over an invalid chain does not
authorize, and the capability check runs before the PoP check** — the second is
not obvious and it is load-bearing, so `TestCapabilityPrecedesPoP` pins it as a
property rather than leaving it as an emergent consequence of call order. It is
also why a denial's citation is sometimes "earlier" than the test author
expects: an invocation whose arguments the leaf never authorized reports §3.4,
not §7 step 7f, because step 6 refused it first.

### The invariant that governs unverified data

`Decide` reads the chain's payloads once **before** any signature is checked, to
learn the root and leaf `jti`, the depth, and whether any token carries
`invocation_constraints`. The rule, stated in a comment at the call site:

> data read here comes from payloads whose signatures have not been checked, and
> it may only ever ADD a denial — never authorize one.

It feeds exactly two consumers: the audit record's chain fields, which are a log
and not a decision, and the stage-5 gate, which can only refuse. Nothing on the
permit path reads it. This is the general form of the §7 step 2c carve-out,
where the draft itself reads `jti` values out of unverified tokens to detect a
cycle — safe for the same reason, and for no other.

One consequence to keep in mind when reading a trace: the §2.4 fact is
*collected* during that pass but *decided* at stage 5, so a chain that both
carries `invocation_constraints` and fails its signature reports the signature.
`TestDecideDeniesInvocationConstraints` asserts that ordering deliberately.

### Fail-closed, and what the client is told

Two error codes, and the distinction is the point:

- **-32001** `warden: request denied by the authorization policy`. `data`
  carries `stage` and `ref` and nothing else. The client learns which check
  refused and which clause of a public specification says so, which is what
  lets a well-behaved agent adapt. It does not learn the constraint it
  violated: the values in a constraint are the parent's policy, not the child's
  to read back out of a denial. `TestEnforcingRelayDenies` asserts both halves —
  the client's `ref` equals the audit record's, and no constraint value leaks.
- **-32002** `warden: audit sink unavailable`. Not an authorization outcome. A
  proxy that silently starts refusing everything because the disk filled is
  indistinguishable from an authorization bug, and an operator sent to read a
  token chain when the real problem is a full disk has been sent to the wrong
  place. The stderr line says so in as many words.

Both are inside JSON-RPC's -32000..-32099 implementation-defined range.

### The notification bypass — the sharpest thing M2 found

A `tools/call` sent as a JSON-RPC **notification** has no `id`. M1's `inspect`
returned `nil` for it, because with no `id` there is nothing to correlate a
response against, and a pipeline built around correlated request/response pairs
treats it as uninteresting. Enforcing, that is a hole with no floor under it:
the call would have been forwarded unverified, and **the caller does not need a
response for the side effect to land.**

`inspect` now returns a call for every `tools/call`, `id` or not. An
unauthorized one is denied and never forwarded; the audit record is emitted with
`emitNoResponse`, since there will be no response to time. The JSON-RPC error is
still written — a notification is not supposed to get one, but a message warden
refuses is not a message warden is relaying, and silence would leave the client
believing a call happened. `TestNotificationIsNotABypass` names it; a regression
here is silent, which is the only reason the test is worth more than the code.

`-passthrough-only` keeps M1's drop-it behaviour exactly, so the control
measurement still measures the same thing.
`TestPassthroughStillIgnoresNotifications` pins that too.

### The number guard — RFC 8785 collapses values §7 step 7f then cannot tell apart

`jcs.CheckNumbers`, applied at bind, denies any argument containing a JSON
number that RFC 8785 canonicalization would not round-trip. See
`docs/ref/NOTES.md` #7 for the full write-up; the short version is that RFC 8785
serializes numbers through IEEE 754 binary64, so `9007199254740993` and
`9007199254740992` share one canonical form, step 7f cannot distinguish them,
and warden forwards the client's **original** bytes upstream — so the server can
act on a value no PoP committed to and no constraint ever checked.

Two things to not misremember about this:

- **It is not a Go decoding artifact.** `encoding/json` does decode into
  `float64` and does lose the same information, but that loss is invisible to
  step 7f, because both sides of the comparison pass through it and agree.
  `TestCanonicalizeIsUnchangedByAGoValueRoundTrip` confirms it byte-for-byte
  over ±2^53, 1e21, 5e-324 and 30-digit integers. The gap is in the
  canonicalization the draft requires, and an implementation that never touches
  a float has it too.
- **It is deliberately not inside `Canonicalize`.** That function's contract is
  RFC 8785's own test vectors, which is the entire reason M0a is a separate
  milestone; a canonicalizer that refuses inputs the RFC canonicalizes is no
  longer the thing those vectors validate, and folding a policy check into the
  primitive would make a future interop failure unattributable.

### Replay resistance is probabilistic, and that is a known gap

§7 step 7g only: the PoP's `iat` is checked against the clock tolerance window
(`aat.DefaultPoPSkew`), nothing is remembered between requests, and the replay
window is therefore roughly twice the skew. **warden does not satisfy §8.5's
MUST for irreversible or side-effecting tools**, which requires stateful `jti`
tracking.

Deferred to M3 as two problems, not one, because they are two: the per-tool
irreversibility classification (§8.5 conditions its MUST on it and the protocol
carries no way to obtain it — see NOTES.md #9), and the replay state itself.
The second is the same class of problem as the `dev.warden/budget` counters — a
key, a location, a loss policy, a consistency requirement that depends on
deployment topology — and there are four unresolved ADR 0001 issues about
exactly that class. A second state store before the first is settled doubles
the debt and buys no conformance, since the tracking could not be applied
selectively the way §8.5 directs anyway.

### The audit-failure latch

Per-process, never clears, reported under -32002.

- **Per-process, not per-connection.** There is one sink and one file handle; a
  per-connection latch would let the next connection re-discover the failure for
  itself and authorize calls in the window before it did.
- **Never clears.** "The sink recovered" is only observable by writing, and
  writing is what failed. Recovery is fix the sink and restart, which is the
  fail-closed direction and also the one an operator can reason about.
- **Checked first, ahead of every signature.** `(*Proxy).authorize` reads
  `Audit.Err()` before it calls `Decide`. That is right for cost — 415ns against
  469µs at depth 3, measured — and right for a second reason: it removes a
  timing side channel that would otherwise let a caller distinguish a valid
  chain from an invalid one while warden refuses both.
  `TestAuditLatchRefusesEverythingAfterAWriteFailure` asserts `c.dec == nil`,
  i.e. that the pipeline never ran at all.

### The audience policy is a choice, not a reading

`-audience` set ⇒ `aat_aud` is required and must match (§7 step 7d). Unset ⇒ the
claim is not consulted. The draft conditions audience binding on "deployment
policy" and defines no default, so both behaviours are conformant; NOTES.md #8
records it as the deployment-policy choice it is. The flag's help text carries
§8.5's warning, because the operator who needs it is the one running more than
one enforcement point over the same chain population.

### What enforcement costs

Same binary, same machine, `go test -run TestEnforcementLatency ./cmd/wardend
-v`. 300 `tools/call` per mode, nearest-rank percentiles, microseconds,
`overhead = total - upstream`:

```
                     overhead p50   overhead p99
passthrough (M1)         21- 31          37- 79
enforcing, depth 1      430-665        1130-1290
enforcing, depth 3     1070-1085        2030-2250
enforcing, depth 5     1490-1610        2920-3310
```

Ranges over three consecutive runs, not confidence intervals — depth 1 is the
noisy one. **Enforcement costs roughly 0.6 ms at depth 1, 1.0 ms at depth 3 and
1.5 ms at depth 5 in p50**, and about twice that at p99.

**The percentage is meaningless and the microseconds are not.** `internal/
testserver` answers in ~14-23µs p50. Any overhead expressed as a ratio against
a peer that fast is a statement about the peer; the same absolute cost in front
of a real MCP server doing real work would look negligible and would not have
become any smaller. Quote the microseconds.

Note also that the `upstream` column itself rises from ~15µs passthrough to
~40-115µs enforcing. That is not warden: a bound message carries a chain and a
PoP in `_meta`, several KB of it at depth 5, and the test server parses what it
is sent. It is subtracted out of `overhead` by the convention M1 fixed, but it
is a real cost the binding imposes on the upstream and it belongs in M4's
accounting.

Where the time goes, in process, no transport
(`go test -run '^$' -bench . ./internal/proxy`):

```
Decide, depth 1      216µs      Ed25519 verify        37µs
Decide, depth 3      492µs      ParsePoP              17µs
Decide, depth 5      746µs      scanChain (depth 3)   16µs
authorize, latched   415ns
```

A CPU profile of the depth-1 path attributes ~44% to Ed25519 verification
(`edwards25519` field arithmetic, plus ~6% in `NewPublicKey` decompressing the
point once per verify) and most of the remainder to `encoding/json` and JCS
canonicalization. There is no third thing: it is signatures and parsing, and
both are linear in depth. The e2e figure runs 2-3x the in-process one, which is
framing, pipe transit and scheduling on messages several KB larger than M1's.

**Against ROADMAP M4's target of p99 < 1 ms on the stateless path at depth 3:
the current p99 is ~2.1 ms, over by roughly a factor of two.** Recorded as the
starting position, not as a failure — M2's exit criteria do not include it and
nothing has been optimized yet. The profile says where the room is: warden
re-parses and re-canonicalizes every token on every request, and a verified
chain is immutable, so a verification cache keyed by the chain bytes is the
obvious first move if the target has to be met.

### Deliberately not done in M2

- **`invocation_constraints`** — gated, not implemented. A chain carrying the
  member is rejected under §2.4 / ADR 0001, which is the "reject, never ignore"
  half. Enforcing it is M2's second half at the earliest.
- **Budget and rate counters.** No counter exists anywhere. The four deferred
  ADR 0001 issues are about where that state lives and what happens when it is
  lost; none of them are resolved.
- **PoP `jti` replay set.** Above.
- **Revocation, key rotation, operator policy YAML, HTTP/SSE.**

---

## M1 exit state

`wardend` fronts one upstream MCP server over stdio. It spawns the server as a
subprocess, relays JSON-RPC in both directions, and writes one audit record per
`tools/call`. Every exit criterion is covered by a test in `cmd/wardend` or
`internal/proxy`; `go test ./... -race` is green.

**Zero enforcement, and that is structural.** There is no call to
`aat.Verifier`, `core.Subsumes` or any authorization check anywhere in the
request path — `internal/proxy` does not import `internal/core` at all, and
imports `internal/aat/jcs` only so `audit.ArgsDigest` can canonicalize
arguments before hashing them. Decision is always `passthrough`. The reason is
not "M2 will do it": M1's latency figures are the control M4 measures its
enforcement overhead against, so a `Verify` call here, even one whose result is
discarded, would put Ed25519 work into the baseline and deflate M4's reported
overhead. ROADMAP M1 says this explicitly now; it previously said the opposite.

### What the proxy does with `_meta`

Extracts, never interprets. `dev.warden/chain`, `dev.warden/pop` and
`dev.warden/spec` (ARCHITECTURE §3.1) are recorded as presence, token count and
byte size; no token is parsed. Absent is not an error in M1 — a chain that is
absent, partial or malformed is recorded with that outcome and forwarded, which
is §3.1's log-only exception. The record's `chain.root_jti`, `chain.leaf_jti`,
`chain.depth`, `chain.max_depth`, `pop.jti`, `pop.aud` and `budget_state` are
`omitempty`/null and stay that way until M2 has something to put in them —
absent rather than zero-valued, because a zero claims a check ran.

### Framing

`json.Decoder` + `json.RawMessage`, one JSON value per `Decode`, and the exact
received bytes are what gets forwarded. Two consequences worth keeping:

- Partial reads, several messages in one read, and notifications with no `id`
  all fall out of the decoder; there is no length-prefix state machine and no
  `bufio.Scanner` (whose 64 KiB default token cap loses against a 256 KiB
  `MAX_STACK_SIZE` chain).
- **Re-serializing is forbidden, not merely slower.** A decode/encode round trip
  reorders object members and can reformat numbers, which is exactly what JCS
  exists in this repo to prevent. The comment in `clientToServer` says so.

Message and newline go out in a **single** `Write`. Two writes leave a peer
holding an unterminated message, and on an unbuffered pipe a reader that stops
at the end of a value never unblocks the second write — that deadlocked the
first version of the framing test.

A pending `tools/call` is registered in the correlation map **before** the
forward, not after: a fast upstream can have its response decoded by the other
pump before a post-write registration lands, and that response would find no
pending call and go unaudited.

### stdout is protocol-only

One writer to stdout, the proxy. Diagnostics, the upstream's own stderr and the
closing latency report all go to stderr; the audit log goes to its own file
(`-audit`, `-` means stderr). `stdoutIsProtocolOnly` in the failure tests fails
if any line on the client's stdout is not valid JSON.

### Failure handling

- **Upstream dies mid-request.** The unanswered call still gets a record, with
  a `forward` trace step whose outcome is `unanswered`. A proxy that silently
  drops it makes exactly that failure invisible.
- **Upstream emits non-JSON.** The direction is terminated rather than
  resynchronized: a JSON stream has no defined resume point after malformed
  bytes, and guessing one means forwarding message boundaries chosen by
  whatever produced them. Because the client only sees the connection die, the
  stderr diagnostic is deliberately loud — it names the direction
  (`upstream -> proxy`), the byte offset, and that the close was deliberate and
  not a crash.
- **Client closes stdin.** Closing the client's stdin closes the upstream's, so
  a healthy server exits on its own.

`Run` takes whichever pump returns first, then closes both `ServerIn` and
`ClientIn` so the surviving pump's blocked `Read` returns through Go's poller
instead of hanging.

### How "no goroutine leak" is measured

`runtime.NumGoroutine()` before the test, then again after teardown, polling to
a 2-second deadline for the count to return to baseline; the test fails with a
full `runtime.Stack` dump if it does not. No dependency was added for this —
`goleak` would have been the project's second dependency and does not earn it.

The bounded wait is not slack in the assertion. `NumGoroutine` is a sample, not
a barrier: a pump can have returned from `Run` while its goroutine is still a
few instructions from exiting, so comparing immediately fails healthy code. A
goroutine genuinely blocked forever on a read from a closed pipe — the failure a
bidirectional stdio relay actually produces — never goes away, so the deadline
cannot hide one. All three failure tests check the count, not just the exit code.

### The e2e, and why it does not use npx

`internal/testserver` is a ~100-line Go stdio MCP server (`initialize`,
`tools/list`, `tools/call echo`), re-execed from the test binary under
`WARDEN_TEST_ROLE`. It is the e2e's peer so the test runs offline and in CI;
depending on `npx @modelcontextprotocol/server-everything` would make the
transparency claim rest on a registry being reachable.

`TestProxyIsInvisible` runs the same conversation twice — once straight at the
server, once through `wardend` — and compares **the response payloads byte for
byte**, not merely that both succeeded.

**Manual check against the real thing (2026-08-23): passed.**
`@modelcontextprotocol/server-everything` did fetch, and a full
initialize / initialized / tools/list / tools/call conversation through
`wardend` returned `Echo: through warden` with the binding recorded
(`chain 2 tokens, 24B; pop 12B`) and 27 µs of overhead. It is not the repo's
e2e and nothing in CI depends on it.

### The latency baseline — this is M4's control

Measured over 500 `tools/call` through the proxy against `internal/testserver`
(`go test -run TestLatencyBaseline ./cmd/wardend -v`), nearest-rank
percentiles, no interpolation:

```
              p50      p99
total        ~53 µs  ~105 µs   first byte in from client -> last byte out to client
upstream     ~21 µs   ~57 µs   first byte out to upstream -> last byte in from upstream
overhead     ~30 µs   ~55 µs   total - upstream
```

Three independent runs on this machine landed within a few microseconds of each
other. Do not quote these as a spec; re-run them on the machine that produces
M4's numbers.

**The convention M4 must reuse.** The spans are wall clock, and `upstream`
includes pipe transit in **both** directions. That residue is real
proxy-attributable cost booked to the server's column by convention, not by
measurement — a different convention moves the overhead figure, so M4 has to
know which one produced the baseline. Three further choices that go with it:

- `total` starts at **first byte received**, not at "message decoded", so the
  decode of a message that may run to `MAX_STACK_SIZE` is inside the overhead.
  `internal/proxy/stamp.go` exists only to make that timestamp available.
- The audit write happens **after** the response reaches the client, so disk
  latency is outside the measured span by construction.
- The three fields are truncated to whole microseconds independently, so
  `overhead_us` and `latency_us - upstream_us` may disagree by 1.

`-passthrough-only` was redundant in M1 and is load-bearing now: it is what lets
this control be re-measured on a binary that has enforcement compiled in.
`Proxy.Run` requires **exactly one** of passthrough and enforcement — neither
is a default and both together is a startup error — so the flag cannot quietly
mean nothing in either direction. Since M2 it defaults **off**: a guardrail
whose default is "guard nothing" is one flag away from being nothing in
production too. The numbers above were re-measured on the M2 binary; see M2
exit state.

### Deliberately not done in M1

- **`audit.Writer` is synchronous under a mutex**, not §6's async writer. One
  record per tool call is not a throughput problem. Marked `ponytail:`.
- **§6's "audit failure ⇒ fail closed" is not implemented.** It is an M2
  obligation: M1 denies nothing, so there is no decision to withhold.
- **No `wardenctl audit tail`.** The log is JSONL; `jq` reads it.
- **stdio only.** HTTP/SSE stays deferred post-M3.

---

## M0b2 exit state

| Criterion | Status |
|---|---|
| A three-token chain mints and verifies end to end including PoP | met — `TestChainVerifies` (`internal/aat/chain_test.go`) |
| Each of I1–I6 has a test that violates it and asserts denial | met — 11 denial tests, listed below |
| The chain-soundness property green, with a run count | met — 20,000 rapid checks, see below |
| The property mutation-checked | met — detected after 123 tests, recipe below |
| §3.3 capability parsing, structural rules enforced | met — `ParseCapabilities`, `TestDenyTwoCapabilityEntries`, `TestOtherAuthorizationDetailsTypesAreIgnored` |
| §5.3 PoP including step 7f canonical `args` comparison | met — `sameCanonicalArgs`, `TestPoPArgumentComparisonIsCanonical` |

`go test ./internal/...`: **349 pass, 0 fail, 0 skip** (79 in `core`, 130 in
`aat`). `go vet ./...` clean.

The I1–I6 denial tests, all in `internal/aat/chain_test.go`:

```
I1  TestDenyI1IssuerMismatch        child iss is not the parent holder key's thumbprint URI
    TestDenyI1SignedByStranger      correct iss, signature by a key that is not the parent's
I2  TestDenyI2DepthSkip             del_depth jumps by two
    TestDenyI2RaisedCeiling         child raises del_max_depth above its parent's
I3  TestDenyI3ChildOutlivesParent   child exp > parent exp
    TestDenyI3ChildPredatesParent   child iat < parent iat
I4  TestDenyI4AddsTool              4p1
    TestDenyI4WidensConstraint      4p4, via core.Subsumes
    TestDenyI4DropsConstrainedKey   4p2, key set smaller
    TestDenyI4AddsConstrainedKey    4p2, key set larger
I5  TestDenyI5WrongParentHash       par_hash of a sibling parent, everything else valid
I6  TestDenyI6PoPSignedByStranger   PoP not signed by the leaf holder key
```

Plus `TestPermitI4OpenWorldParentGainsKeys`, which is 4p3 and must *pass* —
without it, a single subset check satisfies every 4p2 test above and the trap
closes silently.

### The chain-soundness property

`TestChainAttenuationIsSound` (`internal/core/chainsound_test.go`) is the
milestone's second property:

> for all chains C₀ … Cₙ where `CheckI4(Cᵢ₊₁, Cᵢ) == nil` at every link, and
> all invocations (tool, args): `Cₙ.CheckInvocation` permits ⟹ `C₀.CheckInvocation` permits.

It is the whole-chain statement that I4 plus §7 step 6b compose. `Subsumes`'s
soundness is pairwise and per-argument; this one says no *sequence* of valid
derivations reaches a leaf that authorizes something the root would deny.

`-rapid.checks=20000`: **20,001 chains drawn, 7,923 valid, 2,286 leaf-authorized
invocations checked against the root.** 0.47s. At the default 100 checks: 101
drawn, 32 valid, 10 authorized.

Like the M0b1 properties it **fails if the authorized count is zero**. Blindly
drawn argument values essentially never satisfy a drawn constraint, which makes
the implication hold for want of an antecedent; `genSatisfying` draws values the
leaf's constraint is likely to accept (one draw in five ignores it, so the wild
shapes stay reachable) and raised the authorized rate about 16×. It is a
generator of candidates, never an oracle — `CheckInvocation` still decides.

**The mutation check is part of the test contract here too.** Collapsing 4p2
into a subset check — the exact trap this milestone was warned about — MUST make
the property fail:

```
# internal/core/capability.go, in CheckI4:
#   change  if len(childMap) != len(parentMap) {
#   to      if len(childMap) <  len(parentMap) {
go test ./internal/core/ -run TestChainAttenuationIsSound -rapid.checks=2000   # MUST fail
```

As of M0b2 it fails after 123 tests and shrinks to a root of
`{read_file:{path=not_one_of{}}}` against a leaf that has added an `extra`
argument the root's closed-world map never named. Re-run it by hand after any
change to `genCapabilities`, `genDerivation`, `genInvocation`, or
`genSatisfying`.

### Two findings from implementing §7

**Step 5 is unreachable.** It checks `len(chain) == leaf.del_depth + 1`, but
step 3c pins the root's `del_depth` at 0 and step 4d requires each child to
increment by exactly one, so by the time step 5 runs the equality is already
guaranteed. The draft labels it "(Defense in depth)" and that is exactly what it
is; the check is still implemented. Its corollary — **any prefix of a valid
chain is itself a valid chain**, and containment of the wider prefix authority
rests entirely on PoP — is `docs/ref/NOTES.md` #6, and an M4 adversarial
scenario. `TestChainPrefixIsItselfAValidChain` asserts the acceptance rather
than leaving it emergent and untested.

**Ordering is load-bearing and now pinned.** §5.3 completes chain verification
(steps 1–6) before evaluating the PoP, so a valid PoP over an invalid chain must
not authorize. `TestPoPDoesNotRescueAnInvalidChain` mints an impeccable PoP over
an I4-broken chain and asserts the error names I4, not the PoP. Without the
assertion on *which* error, an implementation that evaluates the PoP first still
passes every other test in the file.

Two implementation notes on the traps STATE.md recorded before the milestone:

- Step 2c's pre-verification parse is `extractJTI`, which splits on `.`,
  base64url-decodes segment 1, and unmarshals into a struct with exactly one
  field. It cannot read `del_depth` or `exp` because there is nowhere for them
  to go. Its result feeds only the duplicate-detection set. `verifyThenParse`
  is the ordinary path: `jws.Parse` (header only, payload stays bytes) →
  algorithm/key consistency → `ed25519.Verify` → `aat.Parse`.
- Step 7f never compares raw JSON or decoded maps. `sameCanonicalArgs` reads
  the raw `hta` member out of the PoP payload, canonicalizes it, canonicalizes
  `json.Marshal(args)` independently, and compares the two JCS byte strings.

## M0b1 exit state

| Criterion | Status |
|---|---|
| All nine §3.4 types with `check` + `subsumes` | met — `internal/core/constraint.go` |
| All 81 core pairs asserted, permitted or rejecting | met — `TestAllCorePairs` (19 permitted, 62 rejecting), `TestPermittedTableMatchesDraft` |
| Soundness property green over a meaningful number of runs | met — 200,000 rapid checks per property, 0 failures |
| `MAX_CONSTRAINT_DEPTH` enforced | met — `TestMaxConstraintDepth`, at parse *and* in `Check`/`Subsumes` for hand-built trees |

`go test ./internal/...`: **300 pass, 0 fail, 0 skip** (77 of them in `core`).

Soundness campaign, `-rapid.checks=200000` on each property:

- `TestSubsumptionIsSound` — independently drawn parent and derived. 200,000
  pairs, 25,022 subsuming (12.5%), ~600k implications checked.
- `TestAttenuationIsSound` — derived drawn as a candidate attenuation of the
  parent, 10% of draws ignoring the parent entirely. 200,000 pairs, 97,992
  subsuming (49.0%), ~2.35M implications checked.

Both tests **fail if the subsuming count is zero**. A soundness property over
independently drawn constraints is vacuous unless `Subsumes` actually returns
true sometimes, and a large value space makes that never happen; the generators
draw from a ten-element scalar pool for exactly this reason, and the guard is
what stops a future generator change from silently turning the property off.

**The mutation check is part of the test contract, not a one-off.** Injecting
`{one_of, not_one_of}` into the permitted table MUST make the soundness property
fail. A property that cannot fail is not evidence. If a future change makes that
mutation pass, the generator has stopped reaching the region.

As of M0b1 it fails after 31 tests and shrinks to `one_of{}` / `not_one_of{}`
with the value `[]`. Re-run it by hand after any change to the generators, the
scalar pool, or the value universe:

```
# in permitted's init, add:  {parent: TypeOneOf, derived: TypeNotOneOf}: alwaysSubsumes,
go test ./internal/core/ -run TestSubsumptionIsSound -rapid.checks=2000   # MUST fail
```

### Completeness probe baseline (non-fatal)

`TestCompletenessProbe` is a measurement, **not an assertion** — it cannot fail
the build and must never be made to. §3.5.1 property 2 permits conservative
incompleteness, so there is no threshold to hold anyone to. It exists so that
M4 triage of "warden denied a derivation that looks legitimate" starts from a
recorded baseline instead of from scratch.

Method: sample pairs where `Subsumes` returned false, then search ~16–32 drawn
values plus the fixed universe for a **witness** — a v with `Cd.Check(v) &&
!Cp.Check(v)`, which proves the rejection was right. No witness means either our
rule was timid, or §4.5's default-deny rejected on type grounds, or the witness
lies outside the sampled space. The split separates the first from the second.

200,000 rapid checks:

```
rejected by one of our §4.5 rules:  23512, no witness   2426 (10.3%)
rejected by §4.5 default-deny:     151286, no witness  46071 (30.5%)

  all        -> all           1348 rejected,    605 no witness (44.9%)
  any        -> any           1673 rejected,    480 no witness (28.7%)
  contains   -> contains       873 rejected,    296 no witness (33.9%)
  exact      -> exact         4927 rejected,      0 no witness ( 0.0%)
  not_one_of -> not_one_of    1436 rejected,      0 no witness ( 0.0%)
  one_of     -> exact         3094 rejected,      0 no witness ( 0.0%)
  one_of     -> one_of        1520 rejected,      0 no witness ( 0.0%)
  range      -> exact         4418 rejected,      0 no witness ( 0.0%)
  range      -> range         3309 rejected,    707 no witness (21.4%)
  subset     -> subset         914 rejected,    338 no witness (37.0%)
```

Reading it: the four set- and value-equality rules (`exact`, `one_of`,
`not_one_of`, and the two cross-type `exact` rules) are **exactly complete** over
this value space — every false they produced had a witness. `range -> range` at
21.4% is mostly the empty-interval case in NOTES.md #4: a parent with crossing
bounds accepts nothing, so no witness can exist, but the bound comparison still
rejects. `all` and `any` inherit incompleteness from §4.5 itself — `all` requires
a *one-to-one* clause assignment, so a single derived clause that subsumes two
parent clauses is rejected although it is semantically sound. That one is the
draft's rule, not our timidity, and `TestAllRequiresBacktracking` pins it.

### New dependency: `pgregory.net/rapid` v1.3.0 (test-only)

First dependency in the project. Against the decision ladder:

- Rung 1 (does it need to exist): yes. The soundness property *is* the M0b1
  deliverable — §3.5.1 property 2 is quantified over all constraint pairs and
  all argument values, and no finite table of examples asserts it.
- Rung 2 (stdlib): `testing/quick` exists and was the real alternative. Rejected
  for one reason: **no shrinking.** An unsoundness counterexample is a pair of
  constraint trees plus a value; unshrunk, it is a wall of random structure
  nobody can read. The mutation check above produced a two-empty-sets
  counterexample precisely because rapid shrank it.
- Rung 4 (already-installed dep): there were none.
- Writing our own recursive tree generator plus shrinker is the other
  alternative. A correct shrinker for a recursive sum type is more code, and
  more subtle code, than the thing under test.

Test-only: no non-test file imports it, so it never enters a `wardend` binary.

---

## M0a exit state

| Criterion | Status |
|---|---|
| Round-trip a signed root token and a signed derived token (mint → serialize → parse → verify signature) | met — `TestRootRoundTrip`, `TestDerivedChainRoundTrip` |
| Every RFC 8785 test vector passes byte-for-byte | met — `internal/aat/jcs`, 0 skipped, no expected value adjusted |
| `go test -fuzz` clean on decode and JCS, no panics | met — 60s each, 0 crashers: jcs 4.25M execs / 145 corpus, jws 8.56M / 207, aat 9.02M / 182 |

`go test ./internal/...`: **223 pass, 0 fail, 0 skip** (179 tests + 34 seed
corpus entries + 10 cases added at closeout).

Cross-implementation vectors, not just self-consistency: RFC 8785 Appendix B
(all 24 valid number rows, keyed by IEEE 754 bits), RFC 8785 §3.2.2/§3.2.3
(published hex dump; property sorting), RFC 8037 Appendix A (Ed25519 JWS
compact serialization byte for byte; published JWK thumbprint), RFC 7638 §3.1
(RSA thumbprint construction).

Re-run at closeout with the seed corpora in place, 30s each, 0 crashers:
jcs 238,548 execs / 175 corpus, jws 4,124,607 / 312, aat 4,225,048 / 261.

**Seed corpora are committed** at `internal/aat*/testdata/fuzz/<Target>/`.
Coverage-guided corpora live in the build cache and are lost; these are what
survives. They run as ordinary subtests under `go test`, so a regression in
decode fails the normal suite, not only a fuzz campaign. Note the argument
types differ: `jcs.FuzzCanonicalize` takes `[]byte`, both `FuzzParse` targets
take `string`.

Zero dependencies. `go.mod` has no `require` block; `go 1.24`.

---

## Layout decision, settled before M0b2 and unchanged by it

**The import direction is `aat → core`, strictly one-way. `core` imports stdlib
only and must never import `aat`, `jws`, or `jcs`.** This is what ARCHITECTURE §7
already says ("`internal/aat` imports `core`; `core` speaks domain types"); it is
written here because M0b2 was the first milestone where a careless call site turns
it into an import cycle in the middle of the §7 algorithm. **It held**: `core`
still imports stdlib only, and the reviewer's test at the end of this section is
what kept `ParseCapabilities` and `HolderKeyURI` on the right sides of the line.

The drift ARCHITECTURE leaves open is *where §7 itself lives*: it assigns "the §7
verification algorithm" to `aat` and "chain, decision" to `core`. Resolution:

- **`core` owns every invariant expressible on domain types** — I1 delegation
  authority, I2 depth monotonicity, I3 TTL monotonicity, I4 capability
  monotonicity — over a `Chain` of domain-typed tokens with no bytes in sight.
  This is what makes the second property test (no valid derivation sequence
  yields a leaf authorizing an invocation the root would deny) writable without
  minting or signing anything.
- **`aat` owns the §7 step *sequence* and the two invariants that are inherently
  about bytes** — I5 cryptographic linkage, which hashes the parent's signing
  input, and I6 proof of possession, which verifies a second signature. `aat`
  parses each token, verifies each signature, projects it to a `core` domain
  token, and calls `core` for the domain invariants.

So §7 orchestration is in `aat` because several of its steps are irreducibly
about the wire (the step 2c pre-parse, signature verification, `par_hash` over
signing inputs), and the attenuation semantics are in `core` because they are
not. A reviewer's test: if a function in `core` needs a base64url segment or a
signature, it is in the wrong package.

## Next 3 tasks

1. **Interop with the Tenuo reference implementation**
   (`github.com/tenuo-ai/tenuo`, draft Appendix E) as a test target: a
   warden-minted chain must verify there, and a tenuo-minted chain must verify
   here. **This is the only test that validates the independent-conformant-
   implementation claim.** RFC vectors validate our JCS, JWS and thumbprint
   primitives against published bytes; they say nothing about whether our
   reading of the *draft* matches anyone else's. Every ambiguity in
   `docs/ref/NOTES.md` is a place where this test can fail while both sides are
   conformant — which is exactly what makes it worth running, and warden now
   has an enforcement point to run it against rather than a library.

   NOTES.md #7 raises the stakes: warden denies argument values another
   implementation will accept. If the interop suite carries a large integer,
   that is the first thing it will find.

2. **M3 — delegation across processes**, plus the two state surfaces M2
   deferred into it. The chain machinery is done and tested; what M3 adds is
   agent B holding its own keypair, `wardenctl` rendering a chain, lineage
   revocation — and, from M2: the PoP `jti` replay set and the per-tool
   irreversibility configuration §8.5 conditions its MUST on. Settle the four
   ADR 0001 state issues **before** writing either, since they decide where
   state lives and what happens when it is lost, and a second store built on an
   unsettled answer is debt taken twice.

3. **Fold the vendored draft back into ADR 0001.** The four issues below, plus
   the §10.3.1 finding, are resolvable against real text rather than against our
   own quotation. Scheduled for the M2 pass and not done in it — M2 spent its
   budget on the request path.

Still deferred, none of it blocking:

- **Revocation (§8.9).** `Verifier` detects a repeated `jti` *within one
  presented chain* (step 2c cycle detection) and nothing more.
- **Key management.** `-trust-anchors` loads a JSON array of JWKs once at
  startup. No rotation, no expiry, no reload.
- **A verification cache.** The obvious answer to the depth-3 p99 above, and
  deliberately not built yet: it is a cache keyed by attacker-supplied bytes in
  front of the authorization decision, which is exactly the kind of thing that
  needs designing rather than adding.

---

## Open decisions

### Deferred ADR 0001 issues (recorded 2026-08-22, to be fixed in the M2 pass — NOT M0a/M0b)

- **ADR §3 must cite draft §8.1.2.** The draft explicitly lists cumulative /
  frequency-of-use control as a threat it does not mitigate, and points to rate
  limiting as a complementary control. Our contribution is therefore "the
  extension registry cannot host the complementary control the draft points to",
  not "we found an overlooked gap". Also cite §8.5 as precedent that
  enforcement-side state is already part of the model.

- **The §10.3.1 criterion-2 relocation (ADR B3) is incomplete.** §3.5.1's *Sound*
  property is itself quantified over argument values. Relocating only §10.3.1
  leaves the contradiction in place. Soundness for invocation-granularity types
  must be restated over counter states: subsumes(Cd,Cp) => for all states S,
  Cd.check(S) implies Cp.check(S).

- **ADR §4 Counter state, obligation 1 is wrong as written.** "Every ancestor's
  counter, one per token on the chain" — tokens carrying no instance of that
  type have no counter. Should read "every ancestor carrying an instance of
  that type".

- **State-loss detection has a hole.** Timer snapshots plus "stale = older than
  the oldest live token's iat" does not detect a crash between snapshots: spend
  since the last snapshot is silently refunded. Either charge durably before
  PERMIT, or state the bounded loss explicitly. Also record single-`wardend`-
  instance as a declared v1 non-goal (in-memory counters are not shared).

### Still open from Phase 1

- **D3 (CEL)** revisited with evidence at M2 exit, per ROADMAP.
- **Whether the draft author agrees the granularity gap is real.** ADR 0001 is
  written to be sendable to `niki@tenuo.ai` largely as-is. Not sent — Igor's call.

### Enforcement-time policy

Settled in M2. `MAX_DELEGATION_DEPTH` (§4.3) is `-max-delegation-depth`,
default 8 — the draft recommends no value, topology decides. `MAX_IAT_SKEW` and
`MAX_TOKEN_LIFETIME` (§4.4) are wired as `core.Limits{maxDepth, 30, 90 days}`
and are **not** flags yet, because nobody has needed to move them and a flag
nobody sets is a flag that goes stale. `MAX_TOKEN_SIZE` (§4.3.1) is enforced
inside `aat` since it bounds an attacker-controlled decode path; it is a package
variable rather than a constant, since 64 KiB is only RECOMMENDED and
ARCHITECTURE wants it as operator config. A non-positive value fails closed
rather than meaning "unlimited".

Still absent: the static operator policy YAML from ROADMAP M2. Authority comes
entirely from the chain today. That is the right order — an operator overlay
that can only narrow is a straightforward addition on top of a working §7 path,
whereas one written first would have had nothing to narrow.

---

## Conventions in force

- Conventional commits, one logical change per commit.
- New dependency ⇒ one-line justification against the decision ladder in the
  commit that adds it. **One dependency: `pgregory.net/rapid`, test-only**
  (justified under M0b1 exit state above). Nothing in a shipped binary.
- Any divergence from AAT draft-01 gets an ADR entry. Any *ambiguity* in
  draft-01 gets an entry in `docs/ref/NOTES.md` — that is the difference
  between "we chose differently" and "the draft did not say".
- STATE.md updated at the end of every session.
