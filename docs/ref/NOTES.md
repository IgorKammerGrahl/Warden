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
