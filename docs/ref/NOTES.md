# Spec ambiguities found while implementing

Working notes on places where `draft-niyikiza-oauth-attenuating-agent-tokens-01`
underdetermines behaviour — that is, where two conformant implementations can
disagree. Not a bug list and not a divergence list: a divergence from the draft
gets an ADR, this file records where the draft does not say enough to diverge
*from*.

Each entry: what the text says, what it leaves open, what warden does, and
whether it is worth raising with the author.

---

## 1. "a UUID" is undefined for the `jti` lowercase rule

**Where.** §3.2 Table 1, `jti`: REQUIRED, and "if it is a UUID it MUST be the
lowercase hyphenated form of RFC 9562". UUIDv7 is a SHOULD, not a MUST, so a
`jti` that is not a UUID at all is explicitly permitted.

**What is open.** The draft never says what makes a `jti` "a UUID". The rule is
conditional on a predicate it does not define. Candidates an implementer will
reach for, in increasing strictness:

1. 36 characters, hyphens at 8/13/18/23, hex elsewhere — case-insensitive.
2. The above, plus a valid RFC 9562 version nibble (1–8) at position 14.
3. The above, plus a valid variant (`8`/`9`/`a`/`b`) at position 19.

They disagree on real inputs. `0195...-Bf3A-...` in uppercase is rejected under
all three. But a 36-character hex-and-hyphen string with version nibble `0` or
`f` — `00000000-0000-0000-0000-000000000000`, the nil UUID, or a random hex
identifier that happens to be shaped like one — is "a UUID" under reading 1 and
is not under readings 2 and 3. An issuer using reading 2 may mint such a `jti`
in uppercase, believing the rule does not apply; a verifier using reading 1
denies the token. Both are conformant.

The consequence is not cosmetic. `jti` is the replay-cache key (§7 step 2c,
§8.4), so a disagreement about case normalization is a disagreement about
whether two presentations are the same token.

**What warden does.** Reading 1, the loosest predicate, in
`checkUUIDCase`/`looksLikeUUID` (`internal/aat/token.go`). Rationale: it makes
the MUST apply to the largest set of inputs, so warden rejects a superset of
what stricter readings reject and never accepts a token another implementation
would deny on this rule. Version and variant nibbles are deliberately not
inspected — validating them would *narrow* the rule.

**Worth raising.** Yes, and cheap to fix in the draft: one sentence pinning the
predicate, or dropping the conditional entirely in favour of "MUST be lowercase
if it matches the RFC 9562 textual format".

---

## 2. An empty `constraints` array is only forbidden for a derived `any`

**Where.** §4.5, the `any` bullet: "The derived `any` MUST contain at least one
clause." §3.4 Table 2 says only that `all` and `any` carry `constraints
(array)`.

**What is open.** Three of the four positions are unlegislated: a *parent*
`any` with `constraints: []`, and `all` with `constraints: []` in either
position. They are not degenerate curiosities — they have opposite meanings.
An empty `all` is a vacuous conjunction and accepts **every** value, so it is a
`wildcard` spelled obscurely. An empty `any` is a vacuous disjunction and
accepts **no** value, so it is an unsatisfiable constraint that makes the tool
call it guards permanently undeniable-by-omission.

They disagree on real inputs. An issuer emitting `{"constraint_type":"all",
"constraints":[]}` for "no restrictions configured" — a natural thing for a
policy compiler to produce from an empty rule list — is emitting a wildcard.
An implementation that rejects the token and one that treats it as a wildcard
are both conformant, and the difference is the difference between denial and
unrestricted access to that argument. Worse, a parent `any: []` accepts
nothing, so *every* derived constraint vacuously satisfies I4 against it; an
implementation that permits it has a chain link where subsumption is
meaningless.

**What warden does.** Rejects `constraints: []` at parse time for both `all`
and `any`, in either position (`decodeClauses`, `internal/core/constraint.go`).
Rationale: the one thing the draft *does* say is a MUST NOT, and neither empty
form expresses an intent that cannot be written unambiguously — `wildcard` for
the first, omitting the capability entirely for the second. Rejecting is
fail-closed and costs an issuer nothing. It does mean warden denies a token
another conformant implementation accepts, which is an interop risk, not a
security one.

**Worth raising.** Yes. One sentence generalising the existing MUST to both
composite types and both positions would close it.

---

## 3. Unrecognized *members* inside a constraint object are unlegislated

**Where.** §3.4: "Enforcement points MUST deny authorization if they encounter
a `constraint_type` they do not recognize (fail-closed behavior)", immediately
followed by "Enforcement points MUST ignore unrecognized top-level JWT claims".

**What is open.** The draft legislates unknown constraint *types* (deny) and
unknown *top-level claims* (ignore), and says nothing about an unknown member
inside a recognized constraint object — `{"constraint_type": "range", "min": 0,
"step": 2}`. Reading it by analogy to the top-level claim rule gives "ignore
`step`". Reading it by analogy to the fail-closed rule one sentence earlier
gives "deny".

They disagree on a real input, and the disagreement is not symmetric in risk.
Every unrecognized member an implementation ignores is a restriction the issuer
wrote and the enforcement point did not apply — which is exactly the failure
§3.5.2 spells out for unrecognized extension types: "Silently omitting that
check would violate the attenuation guarantee." The top-level-claim analogy
would licence exactly that omission inside `authorization_details`, where the
fail-closed rule is explicitly in force.

**What warden does.** Rejects any member a core type does not define, per §3.4
Table 2 (`parseConstraint`, `internal/core/constraint.go`). The §3.5.2 argument
is the deciding one: a constraint object is the place where an ignored member
is a dropped restriction.

**Worth raising.** Yes. The fail-closed sentence is about `constraint_type`
specifically; it should also say what to do with members.

---

## 4. A `range` whose bounds cross is not addressed

**Where.** §3.4 Table 2, `range`: "Argument MUST be a number satisfying the
specified bounds. Both bounds are optional."

**What is open.** `{"constraint_type": "range", "min": 10, "max": 5}` satisfies
every stated requirement — both members are numbers — and denotes the empty
interval. One implementation rejects it as malformed at parse; another accepts
it as a constraint that no argument satisfies. Both are conformant.

The disagreement is visible in §4.5 too. An empty parent range is subsumed by
everything semantically (nothing satisfies it, so the implication holds
vacuously), but warden's bound comparison will reject most derived ranges
against it — conservative, and permitted by §3.5.1 property 2, but a second
implementation doing the semantic thing would accept a chain warden denies.

**What warden does.** Accepts it and lets `check` reject every argument. The
draft states no well-formedness rule relating the two bounds, and inventing one
would reject a token another implementation accepts for no security gain — an
empty range is already the most restrictive constraint expressible.

**Worth raising.** Low priority. It is a corner an issuer reaches only by
mistake, and both readings are safe. One sentence would still settle it.

## 5. §4.5 declares no rule for pairs that are plausibly sound attenuations

**What the draft says.** §4.5 gives a subsumption rule per (derived, parent)
type pair: three rules for a derived `exact`, seven same-type rules, the
wildcard row, and one explicit prohibition ({`one_of`, `not_one_of`}). §3.5.1
property 2 makes everything else default-deny: an undeclared pair is not
subsumption, so the derivation is rejected.

**What it leaves open.** Whether the undeclared pairs are undeclared because
they are unsound, or only because nobody wrote them down. The draft does not
say, and the two are not distinguishable from the text.

`TestCompletenessProbe` measures the gap. Over 200,000 rapid checks it searched
for a *witness* behind every `Subsumes` false — a value the derived constraint
accepts and the parent rejects, which proves the rejection was right. Of the
151,286 rejections that came from default-deny rather than from a declared
rule, **46,071 (30.5%) had no witness**. Some of that is the sampled value
space being too small to contain one, but the shape of the residue is
suggestive: a derived `exact` under a parent `not_one_of` that does not exclude
its value, an array-valued `exact` under a parent `subset` that allows its
elements, an `all` whose every clause narrows a single-typed parent. Each is a
real attenuation by the plain meaning of §3.4, and each is denied.

**What warden does.** Denies them, exactly as written. Default-deny is the
safe direction — §3.5.1 property 2 constrains only false positives, and
warden's `permitted` matrix is an allowlist for that reason. The cost is
interop: an issuer that mints a semantically attenuating derivation across an
undeclared pair produces a chain warden rejects, and a more liberal
implementation might not.

**Worth raising.** Yes, as an observation rather than a defect report. The
question for the WG is whether §4.5's table is meant to be exhaustive — in
which case a sentence saying so would close it — or whether the missing pairs
are an oversight to be filled in. Either answer is implementable; the silence
is what costs.

## 6. §7 never states that prefix presentation is safe, and it is safe only by PoP

**What the draft says.** §7 verifies the chain it is given. Step 3c requires the
root's `del_depth` to be 0, step 4d requires each child to increment it by
exactly one, and step 5 then checks `len(chain) == leaf.del_depth + 1` — a check
the draft itself labels "(Defense in depth)", and which the two preceding rules
have already made unreachable.

**What it leaves open.** The consequence. **Any prefix of a valid chain is
itself a valid chain under §7.** An intermediate holder can present the chain
truncated at its own token and be authorized for that prefix-leaf's capability
set — which is *wider* than the real leaf's, since every link attenuates. The
draft never says this, and never says why it is acceptable.

It is acceptable, and the reason is a single mechanism: step 7b requires a PoP
signed under the presented leaf's `cnf.jwk`. Only the holder of that key can
produce one, and that holder legitimately held that authority — presenting the
prefix grants it nothing it did not already have. The property is sound.

What is missing is that the draft relies on this without noting the reliance.
Compare §4.6, where `par_hash` exists *precisely because* a signature plus I1 do
not bind a child to a unique parent instance — the draft identifies the gap and
adds a redundant binding to close it. Here the same class of reasoning applies
and no second mechanism appears: authority containment across prefixes rests
entirely on PoP, with nothing behind it. A conformant implementation that added
a PoP-less "verify the chain only" mode — for an audit tool, a dry-run
endpoint, a debugging CLI — would silently lose the property, and §7 gives its
author no reason to suspect that mode is different in kind.

**What warden does.** Accepts prefixes, because §7 says to.
`TestChainPrefixIsItselfAValidChain` asserts the acceptance rather than leaving
it as an untested emergent behaviour, and records the reasoning above at the
call site. `Verifier.Verify` takes the PoP as a required argument, not an
optional one: there is no code path through it that authorizes without step 7.

**Worth raising.** Yes. One sentence in §7 or §8 — "note that any prefix of a
valid chain is a valid chain; containment of the wider prefix authority depends
on the §5.3 proof of possession" — costs the draft nothing and closes the trap
for the implementer who is about to write the dry-run mode.

**M4:** prefix presentation belongs in the adversarial corpus, alongside the
I1–I6 violations. The attacker case is not the legitimate holder truncating
their own chain; it is a holder who has obtained a *downstream* token's chain
and truncates it to a prefix whose PoP key they control, and the test asserts
that only the PoP stops them.

## 7. RFC 8785 collapses integers a tool can still act on, and §7 step 7f inherits it

**What the draft says.** §5.2 defines `hta` as the invocation's argument map and
§7 step 7f binds the invocation to the PoP by comparing canonical forms:
canonicalize the presented arguments per RFC 8785 and compare against the
canonicalization of `pop_jwt.hta`. §3.3 checks constraints against the same
argument values. Nothing anywhere restricts what a JSON number may be.

**What it leaves open.** RFC 8785 §3.2.2.3 serializes numbers through ES6
`Number::toString`, i.e. through IEEE 754 binary64. Every JSON number outside
binary64's exactly-representable range therefore has a canonical form that is
not its own value, and — the part that matters — **two distinct numbers can
share one canonical form.** `9007199254740993` and `9007199254740992` are both
`9007199254740992` canonically. So are `1e400` and `2e400`, as `null`.

Step 7f cannot tell them apart. A PoP that committed to one matches an
invocation carrying the other, and it matches *correctly* by the letter of the
step: the two canonical forms are equal, because canonicalization is where the
distinction was lost. The same collapse reaches §3.3: a `range` or an `exact`
over such a value is checked against a number the client did not send.

Whether that is exploitable depends on something outside the draft — what the
enforcement point forwards. An enforcement point that reconstructs the request
from the canonical bytes is safe, because then the value the tool executes is
the value that was checked. A proxy that relays the client's original bytes,
which is what transparency requires and what warden does, is not: the upstream
server parses `9007199254740993` with whatever precision it has, and acts on a
value no PoP committed to and no constraint ever saw. The draft describes an
enforcement point without saying which of the two it is, so both readings are
conformant and only one of them is safe.

This is not an artifact of any one language's JSON decoder. Go's
`encoding/json` decodes numbers into `float64` and loses the same information,
but that loss is invisible to step 7f — both sides of the comparison pass
through the same transform and agree, which we confirmed byte-for-byte
(`TestCanonicalizeIsUnchangedByAGoValueRoundTrip`, over ±2^53, 1e21, 5e-324 and
30-digit integers). The gap is in the canonicalization the draft normatively
requires, and an implementation that never touches a float has it too.

**What warden does.** Rejects, at bind, before any signature work, citing §7
step 7f: `jcs.CheckNumbers` re-serializes each number literal through binary64
and denies the call when the result is not numerically equal to what arrived.
`TestBindDeniesAmbiguousNumbers` pins it.

Deliberately **not** folded into `jcs.Canonicalize`. That function's contract is
RFC 8785's own test vectors — the property M0a exists to establish — and a
canonicalizer that refuses inputs the RFC canonicalizes is no longer the thing
the vectors validate. Keeping the check separate is also what keeps a future
interop failure attributable: a mismatch against another AAT implementation is
then a disagreement about the protocol, not about a policy we baked into a
primitive.

**Worth raising.** Yes, and this is the strongest of these entries. The fix in
the draft is one sentence in §5.2 or §7 — either "arguments MUST NOT contain
numbers outside the range exactly representable per RFC 8785 §3.2.2.3" or
"enforcement points MUST forward the canonical form" — and without it, argument
binding is exact for every value except the ones an attacker would choose.

## 8. Audience binding is delegated to deployment policy, so the default is unspecified

**What the draft says.** `aat_aud` is OPTIONAL (§5.2). §5.3 item 3 and §7 step
7d both condition it identically: "when deployment policy requires PoP audience
binding". §8.5 adds a SHOULD for deployments with multiple enforcement points,
and states the consequence of going without — a PoP captured at one enforcement
point is replayable at another that accepts the same chain, tool and arguments
inside the timestamp window.

**What it leaves open.** What an enforcement point does when its deployment
policy says nothing. The draft delegates rather than underspecifies, which is a
reasonable thing for a protocol to do; the effect on interop is the same as an
ambiguity, because the delegation has no default. One implementation requires
`aat_aud` always and rejects every PoP that omits it; another ignores the claim
entirely; both are conformant, and a client that works against one fails against
the other for reasons neither's error message will explain.

**What warden does.** `-audience` is the deployment policy, made explicit:
set it and `aat_aud` is required and must match; leave it unset and the claim is
not consulted. This is a **choice**, not a reading — the draft permits the
opposite default and warden is not entitled to claim otherwise. The asymmetry is
deliberate in one direction only: a proxy that required an audience nobody
configured would deny every call at startup, and a fail-closed default that is
guaranteed to fail is a broken default rather than a safe one. The safety is
moved to where §8.5 puts the risk — an operator running more than one
enforcement point over one chain population needs the flag, and that is stated
in the flag's own help text rather than left to be discovered.

**Worth raising.** Marginally. A sentence naming the default for deployments
that have not decided would help, but the draft's position is defensible and the
cost here is configuration, not correctness.

## 9. §8.5's replay MUST is conditioned on a fact the protocol never carries

**What the draft says.** §8.5 is unusually direct. The timestamp window gives
"probabilistic replay resistance and is appropriate only for idempotent,
read-only tool invocations where duplicate execution is harmless." For
invocations that are irreversible or have significant side effects, enforcement
points "MUST implement stateful jti tracking for PoP JWTs and MUST NOT rely
solely on the timestamp window." §7 step 7g specifies only the window.

**What it leaves open.** How an enforcement point learns which invocations those
are. Nothing in an AAT chain, a PoP, or the invocation says whether a tool
writes; the capability names a tool and constrains its arguments, and §3.3's
vocabulary has no notion of a side effect. So the MUST is conditioned on a
classification the protocol provides no way to obtain, and an enforcement point
fronting tools it did not author — which is warden's entire premise, and MCP's —
cannot even apply it selectively the way the text directs. It can track every
`jti`, track none, or take the classification from somewhere outside the
protocol. §8.5's closing paragraph then declines to define the storage backend
or the consistency model, which is fair for a protocol document but means the
one mechanism the draft mandates is also the one it specifies least.

**What warden does.** §7 step 7g only: the PoP's `iat` is checked against the
clock tolerance window, and nothing is remembered between requests. Replay
resistance is therefore probabilistic, bounded by roughly twice the skew, and
warden does not currently satisfy §8.5's MUST for side-effecting tools. Stated
plainly rather than left to be inferred from an absence.

Deferred to M3 as two separate pieces, because they are two problems: the
per-tool irreversibility configuration (operator-supplied, since the protocol
cannot carry it) and the replay state itself. The second is the same class of
problem as the `dev.warden/budget` counters — a key, a location, a loss policy,
and a consistency requirement that depends on deployment topology — and there
are four unresolved ADR 0001 issues about exactly that class. Adding a second
state store before the first one is settled doubles the debt for no gain in
conformance.

**Worth raising.** Yes, as a question rather than a defect: how is an
enforcement point that did not author its tools meant to obtain the
irreversibility classification §8.5's MUST depends on? If the answer is "out of
band, by configuration", the draft should say so, because the current text reads
as though the enforcement point already knows.
