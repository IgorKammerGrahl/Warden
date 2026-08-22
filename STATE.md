# warden — STATE

Updated: 2026-08-22 (M0a closed)

This file is the cold-start handoff. A session that has read this and
`docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` should be able
to start M0b without re-exploring the repo.

## Current position

**M0a is complete and committed.** M0b has not started.

M0a was encoding and crypto only. Everything in `internal/aat` is
**single-token**: a token's own claims, its own signature, its own shape. There
is no chain logic anywhere in the tree yet.

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

## Next 3 tasks (M0b)

1. **M0b — AAT semantics.** The nine §3.4 core constraint types with `check`,
   §4.5 `subsumes`, the §7 eight-step chain verification algorithm, §5.3 PoP
   verification, and the two property tests (subsumption soundness, chain
   soundness). Gated on M0a's exit criteria, which are met. Two things already
   identified and deliberately left for this milestone:
   - **§3.3: root and leaf tokens MUST contain exactly one
     `attenuating_agent_token` entry.** Checkable for roots today, but
     leaf-ness is not single-token knowable, and it needs
     `authorization_details` parsed rather than opaque. Not half-built in M0a.
   - **§4.4 (I3) `derived.iat >= parent.iat`** and the rest of I1–I5, all
     pair-quantified and therefore absent from `validate`. The one line of I2
     that *is* single-token quantified (`del_depth <= del_max_depth`) is
     already enforced.

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
  commit that adds it. **Still zero dependencies.**
- Any divergence from AAT draft-01 gets an ADR entry. Any *ambiguity* in
  draft-01 gets an entry in `docs/ref/NOTES.md` — that is the difference
  between "we chose differently" and "the draft did not say".
- STATE.md updated at the end of every session.
