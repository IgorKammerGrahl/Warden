# warden — STATE

Updated: 2026-08-22 (M0b1 closed)

This file is the cold-start handoff. A session that has read this and
`docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` should be able
to start M0b without re-exploring the repo.

## Current position

**M0a is complete and committed. M0b1 (constraint vocabulary) is complete.**
M0b2 has not started.

M0a was encoding and crypto only. Everything in `internal/aat` is
**single-token**: a token's own claims, its own signature, its own shape.

M0b1 added `internal/core`: the nine §3.4 constraint types with `check`, the
§4.5 `subsumes` matrix, and the §3.5.1 soundness property test. It is
**single-constraint and single-pair**: one constraint against one argument
value, one derived constraint against one parent constraint. **There is still
no chain logic anywhere in the tree** — nothing walks a token list, nothing
implements §7, nothing verifies a PoP against a chain. That is M0b2.

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
internal/core/                               §3.4 constraints: check, §4.5 subsumes
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
`MAX_TOKEN_SIZE`. Knows nothing about constraint semantics or chains.

**`internal/core`** — the domain layer, stdlib-only, no wire format. Owns the
§3.4 argument-constraint vocabulary (nine types, `Check`), the §4.5 subsumption
matrix (`Subsumes`), and §3.4 `MAX_CONSTRAINT_DEPTH`. Knows nothing about JWTs,
`authorization_details`, or chains. `ParseConstraint` takes the raw JSON of one
constraint object and is the only producer of validated `Constraint` values.

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

Four things a caller must know before using this:

1. **`Parse` does not verify.** A `*Token` from `Parse` is structurally valid
   and cryptographically unattested. §7 step 2c requires reading `jti` from an
   unverified payload, so `Parse` runs on attacker-controlled bytes by design.
2. **`Verify` is single-token.** Signature plus algorithm/key consistency. It
   does not walk a chain, check I1–I5, or evaluate constraints. *Choosing* the
   key is chain verification's job and does not exist yet.
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

## Layout decision, settled before M0b2 writes any chain code

**The import direction is `aat → core`, strictly one-way. `core` imports stdlib
only and must never import `aat`, `jws`, or `jcs`.** This is what ARCHITECTURE §7
already says ("`internal/aat` imports `core`; `core` speaks domain types"); it is
written here because M0b2 is the first milestone where a careless call site turns
it into an import cycle in the middle of the §7 algorithm.

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

## Next 3 tasks (M0b2)

1. **M0b2 — chains.** The §7 eight-step chain verification algorithm, §5.3 PoP
   verification, the I1–I5 invariants as a whole, and the chain-soundness
   property test. This is where `authorization_details` gets parsed into
   capabilities and where `core.Subsumes` acquires its caller — M0b1 built the
   relation, nothing calls it yet. Two things already identified and
   deliberately left for this milestone:
   - **§3.3: root and leaf tokens MUST contain exactly one
     `attenuating_agent_token` entry.** Checkable for roots today, but
     leaf-ness is not single-token knowable, and it needs
     `authorization_details` parsed rather than opaque. Not half-built in M0a.
   - **§4.4 (I3) `derived.iat >= parent.iat`** and the rest of I1–I5, all
     pair-quantified and therefore absent from `validate`. The one line of I2
     that *is* single-token quantified (`del_depth <= del_max_depth`) is
     already enforced.

   **Two steps of §7 that are easy to get subtly wrong. Read these before
   writing the algorithm, not after a review finds them:**

   - **Step 2c extracts `jti` before signature verification, for cycle
     detection. That is the ONLY permitted pre-verification parse**, and the
     values it extracts MUST be treated as untrusted until that token's
     signature verifies. Everything else parses after. The failure mode is
     quiet: a second "while we're in here" pre-parse of `del_depth` or `exp`
     reads attacker-controlled numbers into the algorithm's control flow, and
     no test that only feeds it valid chains will ever notice.
   - **Steps 4p2 and 4p3 are different rules and must not be collapsed.**
     4p2 requires **exact key-set equality** when the parent's argument-constraint
     map is non-empty; 4p3 allows **any key set** when it is empty. Writing one
     subset check that happens to satisfy both on the test fixtures is the
     natural mistake, and it silently admits derived tokens that constrain a
     different argument set than the parent did.

   Exit: a three-token chain mints, verifies end to end including PoP, and each
   of I1–I6 has a test that violates it and asserts denial.

2. **Interop with the Tenuo reference implementation**
   (`github.com/tenuo-ai/tenuo`, draft Appendix E) as a test target: a
   warden-minted chain must verify there, and a tenuo-minted chain must verify
   here. **This is the only test that validates the independent-conformant-
   implementation claim.** RFC vectors validate our JCS, JWS and thumbprint
   primitives against published bytes; they say nothing about whether our
   reading of the *draft* matches anyone else's. Every ambiguity in
   `docs/ref/NOTES.md` is a place where this test can fail while both sides are
   conformant — which is exactly what makes it worth running.

3. **Fold the vendored draft back into ADR 0001.** The four issues below, plus
   the §10.3.1 finding from the previous pass, are now resolvable against real
   text rather than against our own quotation. Scheduled for the M2 pass.

Then: **M1 — MCP proxy passthrough + audit** in log-only mode.

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

### Enforcement-time policy, not yet implemented

`MAX_DELEGATION_DEPTH` (§4.3), `MAX_IAT_SKEW` and `MAX_TOKEN_LIFETIME` (§4.4).
`MAX_TOKEN_SIZE` (§4.3.1) *is* enforced, because it bounds an attacker-
controlled decode path; it is a package variable rather than a constant since
64 KiB is only RECOMMENDED and ARCHITECTURE wants it as operator config. A
non-positive value fails closed rather than meaning "unlimited".

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
