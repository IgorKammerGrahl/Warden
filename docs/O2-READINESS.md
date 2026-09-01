# -02 readiness: NOTES #7 and #11

**Status: assessment only. No code changed, and none should change until the
-02 draft text exists.** The author's reply settles the direction and not the
wording, and the difference between "validate the original number token" and
the sentence -02 will actually carry is where the implementation lives. What
follows is what warden would have to move, what it would cost, and the one
question that has to be answered before `range` can be implemented at all.

Written 2026-09-01, against HEAD `c07f608`.

## What the author said

Both findings are accepted for -02. On #7 his fix differs from warden's:

1. Validation MUST begin from the **original JSON number token**. Applying
   RFC 8785 to an already-parsed binary64 value cannot detect the collision —
   by then both members of the colliding pair are the same `float64` and there
   is nothing left to compare.
2. Constraint numerics get the same validation **during chain verification**,
   not at first invocation.
3. Consequence: exact integers above 2^53 have to be conveyed as strings.

warden today does (1) for invocation arguments and for its own derived tokens,
and does **not** do (2) — the verify-time refusal was deliberately declined as
an interop divergence (NOTES #7 addendum, and the recorded non-block in
`eval/results/summary.md`). -02 makes that refusal conformant, which is the
whole change.

---

## 1. Where warden touches numeric literals

Fourteen sites. The split that matters is the third column: a site that holds
the original token bytes can implement his rule where it stands, and a site
that holds only a parsed value cannot, at any price short of changing a
function signature.

### Sees the original bytes

| # | Site | What it does with the literal |
|---|---|---|
| 1 | `internal/aat/jcs/jcs.go:59,155` — `Canonicalize` | `dec.UseNumber()`, then `json.Number` through `formatNumber`. This is where the collapse happens, by design: RFC 8785 §3.2.2.3 *is* binary64 serialization, and M0a exists to keep this function equal to the RFC's own vectors. |
| 2 | `internal/aat/jcs/exact.go:37` — `CheckNumbers` | The only function in warden that holds the literal and its collapse at the same time: `UseNumber`, re-serialize through binary64, compare as `big.Rat`. Already exactly "validation begins from the original number token". |
| 3 | `internal/proxy/enforce.go:285` — bind | Runs `CheckNumbers(rawArgs)` on `params.arguments` **before** the `json.Unmarshal` three lines later. `rawArgs` is carried from `proxy.go:673` as `json.RawMessage`, untouched off the wire. The only point in the request path where an argument literal exists and is inspected. |
| 4 | `internal/aat/derive.go:182` — derive | `CheckNumbers(entry)` over the marshalled capability entry. `Derivation.Tools` is `map[string]json.RawMessage`, so the caller's constraint literals survive to here intact. |
| 4b | `internal/aat/token.go:112` — `Mint` | `CheckNumbers(raw)` over the whole marshalled claim set, before the canonicalization that would destroy the evidence. The single gate every signature passes through, derived and root alike. **Added 2026-09-01; see the gap note below.** |
| 5 | `internal/aat/token.go:151` — `Parse` | Canonicalizes `msg.Payload` **and discards the output**, keeping only the duplicate-key and UTF-8 rejections. Every literal in the token — constraint values, `exp`, `iat` — passes through this call and is thrown away. This is the hook -02's rule needs, already positioned and already paid for. |
| 6 | `internal/aat/pop.go:54,76` — `SignPoP` / `ParsePoP` | `SignPoP` canonicalizes before signing; `ParsePoP` requires `bytes.Equal(msg.Payload, canonical)`. Consequence worth its own line: **`hta` can never carry an uncollapsed literal.** The producer's own canonicalization destroys it before the signature, and a payload that skipped that step is rejected as non-canonical. See Q4. |
| 7 | `internal/aat/chain.go:396` — `sameCanonicalArgs` | Reads `hta` back out of the payload as raw bytes rather than re-marshalling `PoPClaims.Args`, so what is compared is what was signed. Literal bytes — but already canonical, per (6). |
| 8 | `internal/audit/audit.go:125` — `ArgsDigest` | Canonicalizes raw args to hash them. Not a decision, but note the consequence: two distinct integers above 2^53 produce **the same `args_digest`**, so the audit record cannot distinguish them either. |
| 9 | `internal/core/constraint.go:209,221,244` — `decodeScalar`, `decodeArray`, `decodeRange` | Receives `raw []byte` and immediately decodes the literal away: `float64` for scalars and bounds, `[]any` of `float64` for sets. Has the bytes; keeps nothing. |
| 10 | `eval/corpus.go:467`, `shakedown2/main.go:544` — `argMap` | `UseNumber` decode so a `json.Number` reaches `hta` and `json.Marshal` writes the literal. Test harness only, and the reason NOTES #7 is reproducible at all. |

### Sees only a parsed value — cannot implement his rule as stated

| # | Site | Why not |
|---|---|---|
| 11 | `internal/aat/chain.go:81,93` — `Verifier.Verify` / `VerifyReport(chain, tool, args map[string]any, popJWT)` | **The load-bearing one.** Arguments arrive already decoded at the API boundary. Everything downstream — step 6b, step 7f, every `Check` — is past the point where the literal existed. An argument-side check inside chain verification is impossible without changing this signature. |
| 12 | `internal/core/capability.go` — `CheckInvocation` → `internal/core/constraint.go:296` `Check(v any)` | `v` is `float64` by documented contract (`constraint.go:294`). `range` type-asserts `v.(float64)` at :309; `equal` is `reflect.DeepEqual` (:622) and the comment there says outright that it relies on `1` and `1.0` having already become the same `float64` — the same identification RFC 8785 makes. |
| 13 | `internal/core/constraint.go:94,100` — `Constraint.Value any`, `Min, Max *float64` | A parsed `Constraint` carries no literal anywhere. `rangeSubsumes` (:473) compares `float64`s. **A verify-time constraint check cannot be written against `core.Constraint`** — it has to run on the bytes, before or beside `ParseConstraint`. |
| 14 | `internal/aat/token.go` — `Claims.IssuedAt`, `Expires`, `DelegationDepth`, `MaxDelegationDepth` | `int64`/`int`, decoded straight from the literal with no `float64` hop, so exact to int64 range and outside the collision class on the read side. But `Mint` canonicalizes claims before signing (`token.go:119`), so an `exp` above 2^53 *would* be signed collapsed and nothing checks it. Unreachable in practice — an `exp` above 2^53 is the year 285-million, and `core.Limits` caps lifetime at 90 days. |
| 15 | `internal/aat/chain.go:404` — step 7f, args side | `json.Marshal(args)` re-serializes the parsed map. In the proxy path those values are `float64`, so this half of 7f is by construction a binary64 round-trip. It agrees with `hta` because both sides passed through the same transform — which is precisely the property that makes the collision invisible to step 7f. |

### One gap found while enumerating — **CLOSED 2026-09-01**

**As found.** `aat.Mint` did **not** run `CheckNumbers`. Only
`Deriver.details()` did. Every root token in the repo is minted through
`aat.Mint` directly — `demo/main.go:91`, `eval/corpus.go:203`,
`shakedown2/main.go:198`, `aattest.go:142,186` — so **root capability literals
got no collapse check at all.** That was consistent with the NOTES #7 addendum
as written (its scope was "warden is the party producing them", meaning
derivation), but the guard was narrower than the addendum reads.

**Closed.** `Mint` now runs `CheckNumbers(raw)` over the marshalled claim set,
before `jcs.Canonicalize` — the ordering is the point, since canonicalizing is
what destroys the evidence, the same relationship bind has at
`enforce.go:285`. Whole payload rather than just `authorization_details`: the
bytes are already in hand, and every other claim is an `int64` or a string that
cannot collapse, so a narrower scope would have cost a loop and bought nothing.
`TestMintRefusesAmbiguousConstraintNumbers` pins both directions — a root
`range` bound of 9007199254740993 is refused, and 9007199254740992, one below
and exactly representable, still mints.

`Deriver.details()` is now redundant for soundness, because `Derive` ends at
`Mint`. Kept deliberately: it fires before the I1–I4 link checks and carries a
`core.Deny` citing §3.4 and RFC 8785 §3.2.2.3 against the constraint entry
specifically, so an issuer gets "your constraint literal is wrong" rather than
"your payload is wrong". `Mint` is the floor under it, not a replacement.

**This does not change the -02 assessment below.** The mint-side check is
warden refusing to *produce* a collapsing literal; the author's rule is about
*verifying* one that arrives from elsewhere, which is still unimplemented and
still the substance of §2. Closing this narrows population (b) in §3 and
nothing else.

---

## 2. What `jcs.CheckNumbers` becomes

### Survives unchanged

**The primitive.** `checkNumber` re-serializes the literal through binary64 and
compares as exact rationals. That is already "validation begins from the
original JSON number token" — it never touches a parsed value, and it is the
one place in warden where the literal and its collapse coexist. No change.

**Its separation from `Canonicalize`.** His rule makes the separation *more*
necessary, not less. The check gains call sites; `Canonicalize` still has to
reproduce RFC 8785's published vectors, which is what makes a future interop
failure attributable to a protocol disagreement rather than to a policy warden
baked into a primitive.

**The bind-time call** (`enforce.go:285`). Already in the right place, already
before the decode. What changes is its status and its citation: today it is a
warden-specific guard justified by an argument about what warden forwards
(§7 step 7f); under -02 it is the normative check, and the `Deny` ref changes
to whatever clause -02 numbers the rule.

### Moves

**A second call site inside chain verification.** The natural home is
`aat.Parse` (`token.go:151`), which already canonicalizes `msg.Payload` and
discards the result. `CheckNumbers(msg.Payload)` there gets, for one extra pass
per token:

- every constraint literal in `authorization_details`, at every token in the
  chain, not just the leaf;
- `exp`, `iat` and any future numeric claim, free;
- no new dependency and no signature change — `Parse` already holds the bytes;
- correct ordering by construction, since `Parse` runs after signature
  verification for derived tokens (`chain.go:167`) and inside `verifyRoot` for
  the root.

The alternative home is `core.ParseCapabilities` / `ParseConstraint`, which also
holds raw bytes. It is narrower (constraint literals only, leaf-relevant only)
and it drags a JCS dependency into `core`, which imports stdlib only by
architectural rule (`constraint.go` package comment, ARCHITECTURE §7).
**`aat.Parse` is the right site.**

One ordering note for the deferred verification cache (STATE.md, "Where the next
milestone starts"): the check has to live *inside* the cached unit, not beside
it. Cached by chain bytes, the same bytes give the same verdict and caching the
check with the decision is correct; a check bolted on outside the cache would
run once and be skipped for every request after.

**What the verdict change looks like.** `eval` case
`jcs-ambiguous-constraint-literal` is on record as a known non-block — a forged
token granting `n == 9007199254740993`, an invocation passing
`9007199254740992`, permitted because both collapse to the same `float64`
(`eval/adversarial.go:123-136`, `eval/results/summary.md`). A verify-time check
flips it to a denial. The corpus goes from **61/61 blocked with 4 documented
non-blocks** to **62/62 with 3**, and T2 from 24/24 with one non-block to 25/25
with none. That single row is the most legible measure of what -02 buys, and it
is already written down, which means it can be quoted back rather than
constructed.

### What `details()` becomes

`derive.go:174-186` stops being a security check and becomes an error-quality
guard.

Once the verifier rejects those bytes, minting them is already prohibited by the
project rule that warden never signs what its own verifier would deny (stated at
`token.go:95-100`). So the mint check is redundant for soundness — twice over, in
fact, since as of 2026-09-01 `Mint` itself checks and `Derive` ends at `Mint`.
It is worth keeping anyway, for one reason that is not redundant: **at mint the issuer is
present and can be told what to write instead; at verify the holder has a signed
token nobody can fix.** Two lines and one call to turn a runtime denial into a
mint-time refusal is the cheapest error message in the codebase.

What actually changes at mint is the *remedy* in the message. Today it is
implicitly "pick a smaller bound". Under his rule it becomes "convey it as a
string" — and for `range` that remedy does not exist yet. See Q1.

---

## 3. What breaks for existing tokens

Nothing, and the reason is worth stating precisely because "nothing breaks" is
the kind of claim that ages badly.

Three populations:

**(a) warden-derived tokens.** `Deriver.details()` has refused a collapsing
constraint literal since M3 (`TestDeriveRefusesAmbiguousConstraintNumbers`). No
warden-derived token in existence carries one. The migration set is empty by
construction, not by inspection.

**(b) warden-minted roots.** Was the weak one: `aat.Mint` had no such check, so a
root *could* have carried a collapsing literal, and the population was empty only
by inspection — every root capability literal lives in `aattest.rootTools`,
`demo`, `eval` and `shakedown2`, and they happen to be strings and small numbers.
**Closed 2026-09-01** (see §1): `Mint` now checks, so this population is empty by
construction like (a), and no root minted from here on can carry one.

**(c) tokens from a third-party issuer.** The only population that could carry
one, and it is empty for an entirely different reason: **no independent
implementation of the draft-01 token format exists** (NOTES #13, #14). tenuo
does not implement it — CBOR warrants over Ed25519, no JWS, no JCS, no RFC 7638,
none of the draft's claim names. There is no other -01 issuer whose output could
be affected.

**So there is no migration question.** The bound that makes it moot is *not*
`MAX_TOKEN_SIZE` — 64 KiB has nothing to do with this. It is the 2^53
exactly-representable bound, plus the fact that warden's mint guard already sits
above it for the only tokens that exist. Two secondary bounds back it up:
`core.Limits` caps token lifetime at 90 days, so even a hypothetical -01 token
carrying a collapsing literal expires inside a quarter of the -02 publication;
and every numeric argument the two shakedowns actually observed against real MCP
servers — `head`, `tail`, `offset`, `length`, all line and byte counts — is
orders of magnitude below 2^53.

**What does break is not a token. It is an expressible policy.**

`range` bounds are `*float64` (`constraint.go:100`) and §3.4 Table 2 gives them
numeric bounds only. "Convey it as a string" is complete for every constraint
type whose predicate is equality or membership — `exact`, `one_of`,
`not_one_of`, `contains`, `subset` — because equality on decimal strings is
exactly as strong as equality on the values they denote. It is **incomplete for
`range`**, the one core type whose predicate is an ordering: lexicographic
comparison on decimal strings is not numeric comparison (`"9" > "10"`), so a
string bound has no meaning under Table 2's predicate without a new rule.

That is the sharpest consequence of his third bullet, and it is a hole in the
remedy rather than in the diagnosis.

---

## 4. What to ask him

Four questions. The first blocks implementation; the rest change what gets
written, not whether it can be.

### Q1 — Does "convey as strings" cover ordered comparison? *(blocking)*

An `exact` of `"9007199254740993"` is sound: string equality is value equality
for decimal strings. A `range` with `"max": "9007199254740993"` is not — §3.4
Table 2's `range` predicate is a numeric comparison, and §4.5's `range`
subsumption compares bounds. Neither has a definition over strings.

Three resolutions, at very different cost:

1. **`range` stays numeric and is therefore capped at 2^53.** Simplest, and it
   has the virtue of saying the limitation out loud rather than leaving
   implementers to find it.
2. **`range` accepts string bounds compared as arbitrary-precision decimals.**
   Needs a new comparison rule in §3.4 *and* a matching subsumption rule in
   §4.5, and every implementation needs a bignum on the constraint path.
3. **A new constraint type** for large-integer ranges.

Proposed text for (1), which is what we would implement absent an answer:

> `min` and `max` MUST be numbers within the range exactly representable per
> RFC 8785 §3.2.2.3. Values outside that range cannot be expressed as `range`
> bounds; convey them as strings under `exact`, `one_of` or `not_one_of`.

### Q2 — What is the scope of the verify-time check?

The whole token payload, or `authorization_details` only?

Whole-payload is *cheaper* for us, not more expensive: `aat.Parse` already
canonicalizes the payload, so the check is one call at a site that exists, and
it covers `exp`, `iat` and every future numeric claim for free.
`authorization_details`-only is narrower and leaves a conformant issuer free to
put a collapsing number in an extension claim that some other member reads.

The two readings diverge on any token carrying a member -02 does not know about,
which is every token once the extension registry gets used. Worth one sentence
in the draft either way.

### Q3 — Does the rejection reach tokens issued before -02?

This is precisely why warden refuses at mint and not at verify today: a
verify-time rejection denies tokens another conforming implementation considers
valid, which is an interop divergence and needs an ADR rather than a commit
(NOTES #7 addendum). -02 makes the rejection conformant. What it does not settle
is whether an enforcement point supporting both versions must accept -01 tokens
that a -02 verifier would refuse.

Concretely, warden can answer this either way: it pins a spec identifier at bind
(`enforce.go`, `MetaSpec` against `SpecVersion`) and can branch the check on it.
The question is which behaviour is conformant, not whether it is implementable.

### Q4 — Where is the argument-side check placed, and against what bytes?

A MUST on the enforcement point at step 6/7, or a MUST NOT on the producer in
§5.2? warden implements the former — it does not trust the producer — but the
difference decides whether a conformant enforcement point is *permitted* to
accept such an invocation from a client it trusts. NOTES #7 offered both
spellings; his reply picks the enforcement-side family, so this asks which half.

Attached to it, an observation the draft should probably carry, because an
implementer will get it wrong otherwise:

> **The check cannot be written against `hta`.** §5.2 requires the PoP payload
> to be JCS-canonical, and the producer canonicalizes before signing — so by the
> time any verifier sees `hta`, the collapse has already happened and both
> members of a colliding pair are identical bytes. Validating `hta` for
> exactly-representable numbers is vacuous: it always passes. The only bytes
> that carry the evidence are the invocation's own `arguments`, before they are
> parsed. warden's check sits there (`enforce.go:285`) for exactly this reason.

That one is not really a question. It is the reason his first bullet is right,
expressed in the place where an implementer would otherwise put the check and
find it does nothing.

---

## What we are not asking

- **Whether the mint-time check stays.** His email settles the direction; the
  mint check is warden's own error-quality choice and needs no ratification.
- **Whether `CheckNumbers` already begins from the token.** It does. That half
  of his fix is implemented and has been since M0a.

## What happens next

Nothing in code. -02 is not published, the author will share a draft first, and
`range` cannot be implemented at all until Q1 is answered. When the draft
arrives, the work is: one call in `aat.Parse`, a citation change in
`enforce.go`, a demotion in `derive.go`'s comment, whatever Q1 forces on
`decodeRange`, and one corpus case moving from the non-block table into the
block rate.
