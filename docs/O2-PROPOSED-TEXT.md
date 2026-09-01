# Proposed text for -02: NOTES #7 and #11

Written 2026-09-01 against
`docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt`. Companion to
`docs/O2-READINESS.md`, which records what warden would have to move; this
document is the draft text itself.

**Convention.** Everything inside a quoted block is proposed draft text, written
to be pasted and edited — normative unless the block says *Non-normative*.
Everything outside a quoted block is ours: rationale, alternatives, and the
places we are not sure. Where we are uncertain the note says so and stays
outside the normative prose.

**One correction to our own record first.** NOTES #7's M3 addendum read "an AAT
payload is JCS-canonicalized before it is signed (§3.1)". §3.1 does not say
that, and neither does anything else in -01: the only JCS requirement in the
draft is §5.2's, on the PoP JWT payload, and step 7f's comparison. AAT payload
canonicalization is warden's own choice. The constraint half of finding #1 is
therefore not "canonicalization destroys the literal in the token" — it is a
determinism failure against §3.4's own requirement that two independent
implementations produce identical results. The argument below is written that
way, and it is the stronger of the two. NOTES #7 has been corrected in place,
with a dated correction line; the copy already sent to the author carries the
wrong citation.

---

# Finding #1 — the admissible numeric domain

## 1.1 The two problems, and why one rule closes both

**Invocation arguments — a binding failure, and it is draft-mandated.** §5.2
requires the PoP JWT payload to be JCS-canonical before signing, and §7 step 7f
compares the canonical form of `hta` against the canonical form of `args`. RFC
8785 §3.2.2.3 serializes numbers through IEEE 754 binary64, so two arguments
denoting different values can share one canonical form. Step 7f cannot separate
them, and it fails *correctly* by the letter of the step: the canonical forms
are equal because canonicalization is where the distinction was lost.

**Constraint literals — a determinism failure, and it needs no canonicalization
to arise.** §3.4 states, of the core types: "The check predicate and subsumes
relation for each type are normative: two independent implementations MUST
produce identical results when evaluating either predicate against the same
inputs." A constraint literal outside the binary64-exact domain does not satisfy
that sentence. An implementation that parses JSON numbers into binary64 — which
is what RFC 8785 makes the interoperable numeric model, and what step 7f's own
note about `1.0` versus `1` already assumes — holds `exact: 9007199254740993`
and `exact: 9007199254740992` as the same constraint. An implementation that
parses exactly holds them as different constraints. The two disagree on the
check predicate for one argument value, and they disagree on §4.5's `range`
subsumption for one pair of bounds. Neither is non-conforming, because -01 never
says which numeric model the predicates are evaluated in.

One rule closes both, because both are the same fact: outside a bounded domain,
a JSON number token does not determine a value that every conforming
implementation agrees on.

## 1.2 New §3.4.1

> ### 3.4.1. Admissible Number Tokens
>
> The check predicates in Section 3.4 and the subsumption rules in Section 4.5
> are required to be deterministic across implementations. The canonical form
> comparison in Section 7 step 7f is required to be an equality test on the
> arguments presented. Both requirements bound the numbers this specification
> can carry, because RFC 8785 Section 3.2.2.3 serializes JSON numbers through
> the ECMAScript `Number::toString` algorithm, that is, through IEEE 754
> binary64. A JSON number written outside the values that algorithm reproduces
> exactly has a canonical form denoting a different value than the number
> written, and two JSON numbers denoting different values can share a single
> canonical form.
>
> A JSON number token is **admissible** if the RFC 8785 Section 3.2.2.3
> serialization of that token exists and denotes the same mathematical value as
> the token itself. A JSON number token is **inadmissible** if that
> serialization denotes a different value, or if RFC 8785 prescribes no
> serialization for it.
>
> `1`, `-1`, `1.0`, `0.5`, `1e21` and `9007199254740992` are admissible; `1.0`
> is admissible because its canonical form `1` denotes the same value.
> `9007199254740993` is inadmissible: its canonical form is `9007199254740992`.
> `1e400` is inadmissible: RFC 8785 prescribes no serialization for it.
>
> Admissibility MUST be evaluated against the number token as it appears in the
> received JSON text. It MUST NOT be evaluated against a parsed numeric value.
>
> An enforcement point that encounters an inadmissible number token MUST deny
> authorization. It MUST NOT canonicalize the token and proceed on the resulting
> value. The pattern is the one Section 3.5.2 applies to unrecognized constraint
> types: proceeding would substitute a value for the one presented, and would
> evaluate the issuer's constraints against a value no party committed to.
> Silently accepting that substitution would violate the attenuation guarantee
> in the same way that silently omitting an unrecognized constraint would.
>
> *Non-normative.* The requirement to evaluate against the received token is not
> a performance preference; the check is only meaningful before parsing.
> Canonicalization — and equally a decode into binary64 — is where the
> distinction between two colliding tokens is destroyed. Once the value has been
> parsed, both members of a colliding pair are the same value, the canonical
> form of that value is admissible, and the check always passes. An
> implementation that applies this rule to a parsed value has implemented a
> predicate that is constantly true.
>
> *Non-normative.* Admissible number tokens are exactly the number tokens that
> canonicalization preserves in value. Two admissible tokens denoting different
> values therefore have different canonical forms, since each canonicalizes to a
> form denoting its own value. Restricting numbers to the admissible domain is
> what makes the comparison in Section 7 step 7f an equality test on the values
> presented rather than on their binary64 approximations.

**Placement.** §3.4 is where the consequential numbers live, and §3.4.1 puts the
definition next to the predicates that need it. If the check is scoped to whole
payloads (§1.4 below), the definition sits under a section titled "Argument
Constraints" while governing `exp` and `iat` as well; hoisting it to §3.2 or to
its own §3.8 costs nothing and changes no other text. We have no preference.

## 1.3 Where it applies — token payloads, at chain verification

The constraint literals are in the token payload, and the payload's bytes exist
only until the claims are parsed. §7 already fixes that moment: step 3b and step
4b both say "after signature verification succeeds, parse the claims". The check
belongs in the same sentence, and needs no new step.

> **§7 step 3b, amended:**
>
> ```
>    b. Verify the root token signature against a key in
>       trust_anchors. After signature verification succeeds,
>       verify that every JSON number token in the root token's
>       decoded payload is admissible (Section 3.4.1). If any
>       number token is inadmissible, DENY. Then parse the root
>       token's claims. All subsequent root checks (3c through
>       3n) operate on parsed claims.
> ```
>
> **§7 step 4b, amended (b1 through b5 unchanged):**
>
> ```
>    b. Verify child signature under the key in parent.cnf.jwk. (I1)
>       After signature verification succeeds, verify that every
>       JSON number token in the child token's decoded payload is
>       admissible (Section 3.4.1). If any number token is
>       inadmissible, DENY. Then verify required claims are
>       present:
>       b1. Verify child.jti is present and is a non-empty
>           string. If absent or not a string, DENY.
>       ...
> ```

Both amendments keep the ordering that makes the check work: it runs on the
decoded payload bytes, after signature verification and before deserialization.
Neither adds a step number, so no existing citation moves.

## 1.4 Scope: whole payload, not `authorization_details` only

We propose whole-payload, and the argument is not that it is safer in some
abstract sense — it is that the narrower scope leaves a hole that the extension
registry will make real.

> *Non-normative, for §3.4.1 or for the step 3b/4b notes.* The check applies to
> every JSON number token in the payload, not only to those inside
> `authorization_details`. A conforming token may carry claims this
> specification does not define (Section 3.4 requires enforcement points to
> ignore unrecognized top-level claims), and a profile that reads such a claim
> reads it from the same payload. Scoping the check to `authorization_details`
> would leave an inadmissible number reachable by any member outside it.

It is also the cheaper reading for an implementation, which is worth stating
because the usual expectation runs the other way: an implementation already
decodes the payload at this point, so the whole-payload scan is one pass over
bytes it is holding, while the narrow scope requires locating
`authorization_details` first and walking it structurally. Warden's site is
`aat.Parse`, which already decodes and discards a canonicalization of the whole
payload; the check is one call there and covers `exp`, `iat` and every future
numeric claim for free.

**Open (non-normative, to the author).** Whole-payload scope has one
consequence worth deciding deliberately rather than inheriting: it makes an
inadmissible `exp` a chain-verification failure. That is unreachable in practice
— `exp` above 2^53 is the year 285-million and §4.4's `MAX_TOKEN_LIFETIME`
bounds it long before — but it means a token is rejected for a claim the
attenuation model does not use. We think that is right, and we are flagging it
rather than assuming it.

## 1.5 Where it applies — invocation arguments, at step 7f

This is the half that changes the algorithm's *interface*, not only a step.

> **§7 Inputs, amended:**
>
> ```
> Inputs:
>   chain:         ordered array of signed JWTs, [root, ..., leaf]
>   trust_anchors: set of public keys trusted as root issuers
>   tool:          the tool being invoked
>   args:          the arguments being passed to the tool, as the
>                  argument object together with the JSON text in
>                  which it was received
>   pop_jwt:       the PoP JWT presented by the agent
> ```
>
> **§7 step 7f, amended:**
>
> ```
>    f. Verify the invocation's arguments against the PoP
>       commitment:
>       f1. Verify that every JSON number token in the received
>           JSON text of the args object is admissible
>           (Section 3.4.1). If any number token is
>           inadmissible, DENY.
>       f2. Verify pop_jwt.hta, when JCS-canonicalized, equals
>           the JCS-canonical form of the args map for this
>           invocation. If the canonical byte sequences differ,
>           DENY.
> ```
>
> *Non-normative.* An enforcement point MAY perform step 7f1 earlier than step
> 7f — at request ingress, before any signature verification — since the outcome
> of the algorithm is unchanged and the check is cheap. Step 7f1 is stated here
> because it is the step whose exactness it establishes.

> **§5.2, proposed note after the whole-payload canonicalization paragraph:**
>
> *Non-normative.* The admissibility requirement in Section 3.4.1 cannot be
> discharged by checking `hta`. This section requires the PoP JWT payload to be
> JCS-canonical before signing, so every number token in `hta` is already a
> canonical form and is admissible by construction; applying the Section 3.4.1
> check to `hta` always passes. The only bytes carrying the evidence are the
> invocation's own arguments as received, before they are parsed. An enforcement
> point that validates `hta` and not the invocation has implemented nothing.

**Implementation note for the author, not draft text.** The `args` input
becoming a pair — value plus received text — is the one place where this finding
costs an implementation more than a call. Warden's verification entry point is
`Verifier.Verify(chain, tool, args map[string]any, popJWT)`: arguments arrive
already decoded, so everything downstream of that boundary, including 6b, every
`Check` and 7f, sits past the point where the literal existed. The check has to
move to wherever the request's JSON text is still intact — for warden, the proxy
ingress, which is where it already is. We expect any enforcement point whose
verification library takes a decoded map to find the same. It is worth one
sentence in -02 saying so, because an implementer reading step 7f1 in isolation
will look for the bytes at the wrong layer.

## 1.6 The blocking question: `range`

"Convey as strings" is complete for `exact`, `one_of`, `not_one_of`, `contains`
and `subset`. Every one of those predicates is equality or membership, and
equality on decimal strings is exactly as strong as equality on the values they
denote. It is not complete for `range`, the one core type whose predicate is an
ordering. Lexicographic comparison of decimal strings is not numeric comparison
— `"9"` sorts above `"10"` — so a string bound has no meaning under Table 2's
`range` row, and none under §4.5's `range` subsumption rule, which compares
bounds. -02 has to pick one.

### Branch A — `range` stays numeric and is capped at the admissible domain

> **§3.4, proposed paragraph after Table 2:**
>
> The `min` and `max` members of a `range` constraint MUST be admissible number
> tokens (Section 3.4.1). A constraint whose `min` or `max` is a string, or an
> inadmissible number token, is malformed; enforcement points MUST deny
> authorization on encountering one.
>
> A value outside the admissible domain cannot be expressed as a `range` bound.
> An issuer that must constrain such a value MUST convey it as a string under
> `exact`, `one_of` or `not_one_of`, whose predicates are equality and
> membership and are therefore well defined over a decimal string
> representation; or MUST use a registered extension constraint type
> (Section 3.5) that defines an ordering over its own value space and satisfies
> the requirements of Section 3.5.1.
>
> *Non-normative.* The admissible domain contains every integer of magnitude at
> most 2^53 and the binary64-representable values beyond it. Deployments
> bounding counts, offsets, sizes, page limits or minor currency units are
> orders of magnitude below that ceiling. The limitation is stated rather than
> left to be discovered, because the failure mode of discovering it late is not
> a rejected token: an implementation that accepts a string bound under a
> numeric predicate compares decimal strings lexicographically, and a
> subsumption check written that way expands authority rather than narrowing it.

§4.5 is unchanged under Branch A.

### Branch B — `range` accepts string bounds compared as exact decimals

> **§3.4, proposed replacement for the `range` row's prose and a following
> paragraph:**
>
> The `min` and `max` members of a `range` constraint are each either an
> admissible number token (Section 3.4.1) or a string in the JSON number lexical
> form of [RFC8259] Section 6. A string bound denotes the exact mathematical
> value of that lexical form; no binary64 rounding is applied to it.
>
> Where either bound of a `range` is a string, the argument value MUST be either
> a number or a string in the JSON number lexical form, and the check predicate
> compares the exact mathematical value of the argument against the exact
> mathematical value of each bound. An argument that is a string not in the JSON
> number lexical form fails the predicate. Comparison MUST NOT be lexicographic.
>
> Implementations MUST evaluate these comparisons at a precision sufficient to
> distinguish the operands exactly. An implementation supporting string bounds
> therefore requires arbitrary-precision decimal comparison on both the check
> path and the subsumption path.
>
> **§4.5, proposed amendment to the `range` bullet:**
>
> Bound comparison uses the exact-value comparison defined in Section 3.4,
> across the number and string forms: a derived bound written as a number and a
> parent bound written as a string are compared by value, not by JSON type. A
> derived `range` whose bounds are strings is a valid attenuation of a parent
> `range` whose bounds are numbers when the exact-value comparison holds, and
> the converse likewise.

### Which we would choose, and why

**Branch A.** Four reasons, in descending order of how much they would survive
working-group argument.

1. **The failure mode of a half-implemented Branch B is an authority
   expansion.** Under A, `{"constraint_type": "range", "max":
   "9007199254740993"}` is malformed and denied. Under B, an implementer who
   reads "string bounds are permitted" and reaches for the language's default
   string comparison has written a subsumption check in which `"9" > "10"`, and
   it will accept a widening derivation. B's soundness lives entirely in one
   MUST NOT that costs a dependency to obey.

2. **B introduces a second value space into a core type, and it disagrees with
   the two equalities already in the draft.** Under B, `range [100, 100]`
   accepts both `100` and `"100"`, while `exact: 100` accepts only `100` — §3.4
   gives `exact` value equality, and a string and a number are not equal. Step
   7f draws the same line: `{"n": 100}` and `{"n": "100"}` have different
   canonical forms and are different invocations. So B leaves one core type
   whose notion of equality crosses the JSON type boundary while every other
   mechanism in the draft holds that boundary. That is the kind of divergence
   that produces a conforming implementation which is nonetheless wrong.

3. **§3.4's own design rule already answers this.** "The core constraint set is
   intentionally limited to constraint types with simple, deterministic,
   format-independent check and subsumes rules... Deployments requiring richer
   policy expressiveness SHOULD use a registered extension constraint type." An
   ordering over arbitrary-precision decimals is precisely the richer
   expressiveness that sentence routes to §3.5 — and §3.5.1 is the machinery
   that would make it safe, since a registration would have to carry the
   decidability, soundness and determinism argument that B would otherwise leave
   implicit in the core.

4. **The cost is small and it is honest.** The ceiling is 2^53. Every numeric
   argument the two warden shakedowns observed against real MCP servers —
   `head`, `tail`, `offset`, `length`, line and byte counts — is orders of
   magnitude below it. Branch A says the limitation out loud in the section
   where an implementer is already reading; Branch B says nothing out loud and
   requires every implementation to acquire a bignum to be correct.

Branch A is also the only branch that can be adopted and then reversed. If a
deployment appears that genuinely needs an ordered constraint above 2^53, an
extension type under §3.5 adds it without changing a line of the core, and the
registration carries the soundness proof. Branch B cannot be walked back once
tokens exist with string bounds in them.

**Open (non-normative, to the author).** Branch A is complete only if the
argument can be conveyed as a string too — `exact: "9007199254740993"` is
useless unless the tool's own schema accepts a string in that position. That is
a deployment constraint, not a protocol one, and we do not think -02 should
legislate it. It may be worth one sentence noting that conveying a value as a
string is a decision about the tool's interface as much as about the token.

---

# Finding #2 — optional constrained arguments

## 2.1 Representation: a `required` member on the constraint

We propose a boolean `required` member, OPTIONAL, default `true`, on the
constraint object that is the direct value of an argument name in a tool's
constraint map. Five reasons, and the last is the one that decides it.

1. **A constraint type cannot reach the decision.** §7 step 6b branches on
   presence in the constraint map — "if that argument is absent from `args`,
   DENY" — before any check predicate runs. Constraint types are dispatched
   after that branch. So no type, core or registered, can make an argument
   optional, which is why §3.3's deferral to "profiles or extension constraint
   types" cannot be discharged as written. The marker has to sit outside the
   type dispatch, and a member does.

2. **The shape already exists in §3.4.** `range` carries `min_inclusive` and
   `max_inclusive`: optional booleans with stated defaults, inside the
   constraint object. `required` needs no new grammar and no new place to put
   it.

3. **Default `true` means no migration and no changed security property.** A
   -01 token and a -02 token that does not opt out verify identically. §3.3's
   claim — the presence of a constraint asserts the issuer has reasoned about
   that argument — holds unchanged for every constraint that stays required, and
   the polarity matches the discipline §3.3 already applies to `wildcard`: the
   permissive reading must be written down explicitly.

4. **Per-argument placement is what §4.5 needs.** Subsumption in §4.5 and step
   4p4 are per argument key. A tool-level list of optional argument names would
   need its own subsumption rule and would not compose with the per-key
   comparison that already exists.

5. **It leaves step 4p2 intact.** Making an argument optional does not remove
   its key from the map; the key stays at every link and carries a flag. Every
   alternative that expresses optionality by *dropping* a key forces 4p2 — the
   step you identified as load-bearing — to relax. This one does not touch it.

**Note on -01 interoperability (non-normative).** A -01 enforcement point that
ignores an unrecognized member inside a constraint object reads
`{"constraint_type": "wildcard", "required": false}` as a mandatory wildcard and
denies an invocation that omits the argument. A -01 enforcement point that
rejects unrecognized members denies too. Both readings are denials; neither is
an escalation, so the marker is safe to deploy against a mixed population. -01
does not actually say which reading is correct — §3.4's fail-closed rule is
scoped to unrecognized constraint *types*, and members inside a constraint
object are unlegislated. That is a separate gap and -02 may want to close it;
whichever way it closes, the conclusion here is unchanged.

## 2.2 §3.3 — replacement text

The three sentences to replace are the ones beginning "Issuers who wish to
permit an argument to be omitted MUST NOT include a constraint for it..." The
guidance there is inverted with respect to the closed-world rule stated two
paragraphs earlier: omitting an argument from the map is what *forbids* it.

> **§3.3, proposed replacement:**
>
> An issuer who wishes to permit an argument to be omitted MUST include a
> constraint for it and set that constraint's `required` member to `false`
> (Section 3.4). Omitting the argument from the constraint map does not make it
> optional. Under closed-world mode an argument the map does not name is
> forbidden, not permitted; the two are opposites, and an issuer relying on
> omission forbids the invocation it intended to allow.
>
> A `required: false` constraint relaxes presence only. An invocation that omits
> the argument is permitted; an invocation that carries it is evaluated against
> the constraint exactly as a required constraint would be. The security
> property stated above is therefore preserved for every invocation that
> supplies a value: the presence of a constraint still asserts that the issuer
> has reasoned about that argument, and no supplied value escapes that
> reasoning. What `required: false` adds is that the issuer has also reasoned
> about the argument's absence.
>
> To authorize an argument without restricting its value, use a wildcard
> constraint (see below). A wildcard constraint is mandatory like any other
> unless it also carries `required: false`.
>
> Presence semantics are defined by this specification and are not delegable.
> Section 7 step 6b branches on an argument's presence in the constraint map
> before any constraint's check predicate is evaluated, so a profile or a
> registered extension constraint type cannot alter them.

That last paragraph replaces "Optional constrained arguments are outside the
core constraint model; profiles or extension constraint types that require such
behavior must define it explicitly." The sentence promises a mechanism the
extension model structurally cannot provide, and an implementer who goes looking
for it in §3.5 will find nothing wrong with §3.5 and conclude the fault is
theirs.

## 2.3 §3.4 — the member

> **§3.4, proposed paragraph following Table 2:**
>
> Any constraint object MAY include a `required` member whose value is a
> boolean. The member is OPTIONAL; its default value is `true`.
>
> `required` governs presence, not value. A constraint whose `required` member
> is `true` or absent is satisfied only by an invocation that supplies the
> argument with a value the constraint accepts. A constraint whose `required`
> member is `false` is additionally satisfied by an invocation that does not
> supply the argument at all; when the argument is supplied, the constraint's
> check predicate is evaluated against it exactly as for a required constraint.
> See Section 7 step 6b.
>
> `required` is meaningful only on a constraint that is the direct value of an
> argument name in a tool's constraint map. Enforcement points MUST reject a
> token in which a `required` member appears on a constraint nested within an
> `all` or `any` clause, or within an extension constraint type's own nested
> constraints.
>
> `required` does not alter closed-world mode's treatment of arguments the
> constraint map does not name. An argument absent from the map is forbidden
> regardless of any `required` member elsewhere in the map.

The rejection of a nested `required` is fail-closed and cheap, and it prevents
the token that reads as if it granted something it did not.

## 2.4 §7 step 6b

> **§7 step 6b, amended:**
>
> ```
>    b. Verify tool is present in leaf_aat.tools. Then, for each
>       argument in args: if the tool's constraint map is
>       non-empty and the argument name is not present in the
>       constraint map, DENY (closed-world mode). For each
>       argument name present in the constraint map, if that
>       argument is absent from args: if that argument's
>       constraint has a `required` member present with the
>       value false, the argument is treated as not supplied and
>       its constraint is not evaluated for this invocation;
>       otherwise DENY (constrained argument MUST be present).
>       For each argument name present in both the constraint
>       map and args, verify the argument value satisfies the
>       constraint, whatever the value of its `required` member.
>       If any constraint check fails, DENY.
> ```

Two words in that step are load-bearing and should survive editing.

**"is not evaluated"**, not "is vacuously satisfied". A vacuous-satisfaction
reading would have to answer what `not_one_of` means applied to no value, and
what a registered extension type's predicate means applied to no value — and
§3.5.1 requires that answer to be deterministic across implementations, so it
would become a registration obligation. No answer is needed if the constraint
simply does not run.

**"whatever the value of its `required` member"** in the last clause. It is the
sentence that keeps `required: false` from becoming an evasion: the marker buys
omission and nothing else. Without it, an implementer can read the relaxation as
attaching to the argument rather than to its presence.

Step 7f is unaffected. An omitted optional argument is absent from `args` and
absent from `hta`, and the canonical forms agree as before.

## 2.5 §4.5 — the subsumption rule, and its proof

> **§4.5, proposed amendment.** Replace "For each argument constraint key
> present in both parent and derived token, the derived constraint MUST be at
> least as restrictive as the parent's constraint." with:
>
> For each argument constraint key present in both parent and derived token, the
> derived constraint MUST be at least as restrictive as the parent's constraint
> in both dimensions: in the value dimension, per the per-type subsumption rules
> below, and in the presence dimension, per the following rule. The presence
> rule is evaluated independently of the constraint types involved and applies
> to every (parent type, derived type) pair the per-type rules permit.
>
> * ***required:*** Let `r_p` be the parent constraint's `required` member and
>   `r_d` the derived constraint's, each defaulting to `true` when absent. The
>   pair is a valid attenuation if `r_d` is `true`, or if `r_p` is `false`. It is
>   invalid if `r_p` is `true` and `r_d` is `false`: a derived token MUST NOT
>   make a required argument optional. Enforcement points MUST reject that pair.
>
> The argument is the one used for the constraint-map key rules above, in terms
> of the set of invocations a constraint map accepts. For an argument key `k`
> with constraint `C`, write `A` for an invocation's argument map. A constraint
> with `required` true accepts exactly the invocations
>
> ```
>   { A : k in A and C.check(A[k]) }
> ```
>
> and a constraint with `required` false accepts exactly
>
> ```
>   { A : k not in A }  union  { A : k in A and C.check(A[k]) },
> ```
>
> which is the required-true set together with the invocations that omit `k`.
> Let `C_d` subsume `C_p` in the value dimension, so that `C_d.check(v)` implies
> `C_p.check(v)` for all `v`. Then:
>
> * `r_p` false, `r_d` true. The derived set is `{ A : k in A and
>   C_d.check(A[k]) }`, contained in `{ A : k in A and C_p.check(A[k]) }`,
>   contained in the parent set. Valid.
>
> * `r_p` equal to `r_d`. Each branch of the derived set is contained in the
>   corresponding branch of the parent set, since `C_d.check` implies
>   `C_p.check` and the omission branch is identical. Valid.
>
> * `r_p` true, `r_d` false. The derived set contains every invocation that
>   omits `k`, and the parent set contains none of them. The empty argument map
>   is such an invocation, so containment fails for every `C_p` and `C_d`,
>   independent of the value dimension. Invalid.
>
> The rule is decidable, sound and deterministic in the sense of Section 3.5.1:
> it is a comparison of two boolean values with a defined default; it returns
> true only in the cases shown above to be containments; and two independent
> implementations evaluating it on the same inputs return the same result.
>
> Where the parent's constraint map is empty (open-world), the derived token MAY
> introduce keys with `required` either `true` or `false`. The open-world set is
> every invocation of the tool, so any closed-world map is contained in it
> whatever its `required` members.

The third case is worth noticing for what it does *not* depend on: it fails for
every pair of constraints, including a derived constraint that is strictly
narrower in value. Making an argument optional is a widening that no amount of
value-narrowing offsets, because it adds a shape the parent never accepted. That
is the same argument §4.5 already makes for dropping a key, at a different
level, which is the sign the rule belongs where we have put it.

> **§6 step 4, proposed amendment.** Replace "For each key, select a constraint
> that is at least as restrictive as the parent's, per the subsumption rules in
> Section 4.5." with:
>
> For each key, select a constraint that is at least as restrictive as the
> parent's, per the subsumption rules in Section 4.5. A derived constraint MAY
> set `required` to `true` where the parent's constraint has `required` `false`;
> it MUST NOT set `required` to `false` where the parent's constraint is
> required.

§6 is the mirror of §4.5 for the producing side and would otherwise tell a
deriving holder to copy the key set without saying what may change on it.

## 2.6 §7 step 4p2 — what it becomes

**Under this proposal alone: unchanged, verbatim.**

That is the answer, and it is the point. 4p2 freezes the argument key set across
the chain because under closed-world semantics the key set *is* the invocation
shape, and freezing it is what makes the shape a property of the signed
capability rather than of the invocation. A `required` marker keeps every key in
every map at every link. Only the flag on a key varies down the chain, and it
varies in one direction. So 4p2 keeps doing exactly what it did, and the new
rule lands beside it:

> **§7 step 4p, proposed new substep (p1 through p4 unchanged):**
>
> ```
>       p5. For each argument key present in both constraint maps
>           for a matched tool, verify the presence relation of
>           Section 4.5: if the parent's constraint has a
>           `required` member absent or true, and the child's
>           constraint has a `required` member present with the
>           value false, DENY.                             (I4)
> ```
>
> **§7 step 4p3, proposed amendment:**
>
> ```
>       p3. For each tool present in both parent_aat.tools and
>           child_aat.tools: if the parent's constraint map is
>           empty, the child's constraint map MAY contain any
>           set of keys, with any `required` members.
> ```

p5 is stated separately rather than folded into p4 so that a failure is citable
as a presence failure and not as a subsumption failure — the remedies are
different, and an issuer told "your constraint does not subsume" when the
constraint is fine and the flag is wrong will look in the wrong place.

**Open (non-normative, to the author).** Dropping a key whose parent constraint
carries `required: false` is *sound*, and 4p2 could be relaxed to permit it. The
derived set would be `{ A : k not in A and the remaining keys are satisfied }`,
contained in the parent's set precisely because the parent accepts omission of
`k`. We are not proposing it, for two reasons: it is the only thing in this
proposal that would make 4p2 conditional on a per-key flag, and NOTES #11 does
not need it — the finding is that a tool with an optional argument is unusable
under any delegation, and the marker alone makes it usable. If -02 does permit
it, it needs three conditions, and the third is the reason the two relaxations
have to be specified together:

1. the parent's constraint for that key has `required` present with the value
   `false`;
2. the child's constraint map remains non-empty, since an empty map is
   open-world per §3.3 and dropping the last key would discard every remaining
   constraint rather than one;
3. the child's tool entry does not permit arguments outside its constraint map,
   since otherwise the child accepts the dropped argument with no constraint at
   all, which the parent accepted only subject to its own.

Condition 3 is vacuous whenever the unknown-argument relaxation is itself
monotone and the parent does not set it, and bites exactly when the parent sets
it and the child keeps it.

## 2.7 Relationship to `allow_unknown`

**Assumption, stated so it can be corrected.** We take `allow_unknown` to relax
the *first* half of closed-world mode — an argument the constraint map does not
name is permitted rather than denied — and `required: false` to relax the
*second* — a named argument may be omitted. Those are the two halves of §3.3's
rule and the two clauses of §7 step 6b. If `allow_unknown` means something else,
every statement below changes. Everything above is independent of it.

**They are independent relaxations, and they meet in exactly one step.** 6b
carries both clauses and each marker relaxes one, so 6b under both is the text
in §2.4 with its first clause conditioned on `allow_unknown`. Nothing else in §6
or §4.5 couples them.

**4p2 is where the two differ, and it is why they cannot be written
separately.** `required` never changes the key set, so 4p2's key-set clause
survives intact. `allow_unknown` does change it: if the parent's tool entry
permits arguments outside its constraint map, then a child that *adds* a key —
and thereby constrains an argument the parent accepted unconstrained — is
strictly narrowing, and 4p2's "no key added" clause has to relax to admit it.
§4.5's own justification for the frozen key set says so in as many words:
"Adding a key would produce invocations that the parent's closed-world check
rejects (the extra argument is unknown)." Under `allow_unknown` the parent's
check does not reject them, and the justification lapses.

> **§7 step 4p2, if both relaxations land in -02:**
>
> ```
>       p2. For each tool present in both parent_aat.tools and
>           child_aat.tools where the parent's constraint map is
>           non-empty:
>           - A key present in the child's constraint map and
>             absent from the parent's is permitted only if the
>             parent's tool entry permits arguments outside its
>             constraint map; otherwise DENY.
>           - A key present in the parent's constraint map and
>             absent from the child's: DENY.
> ```

**Both markers must be monotone, in opposite directions, for the same reason.**
`required` may go `false` to `true` down the chain and never back. `allow_unknown`
may go `true` to `false` and never back — a child that permits unknown arguments
where its parent did not accepts invocations carrying arguments the parent
forbade, which is the widening §4.5 exists to prevent. Both are authority that
can be spent and not created, and both belong in §4.5 as presence-dimension
rules rather than as value-dimension ones.

**Where finding #1 meets finding #2.** Step 7f1 is scoped to the whole `args`
object, not to the arguments the constraint map names. That is deliberate and it
matters more once `allow_unknown` exists: an argument permitted because the tool
entry allows unknown arguments is never evaluated by any constraint, so 7f1 is
the only check it passes through. Scoping the admissibility check to constrained
arguments would leave the unconstrained ones — the ones a `range` never bounded
and no `exact` ever pinned — free to carry a number the enforcement point
verifies as one value and the tool executes as another.

**Two §3.3 sentences that `allow_unknown` contradicts as written**, noted here
because they are in the paragraph our replacement text sits next to and an
editor working on one will be looking at both:

- "Enforcement points MUST enforce closed-world mode and MUST NOT permit
  unconstrained arguments when any constraint is present for the tool (see
  Section 7, step 6b)." This is the sentence `allow_unknown` relaxes, and the
  MUST NOT has to become conditional on it.
- "A token issuer that wishes to allow unconstrained arguments alongside
  constrained ones MUST explicitly include a wildcard constraint for each
  argument that should be unrestricted." Under `allow_unknown` this stops being
  the only way, and the MUST becomes a statement about the closed-world case.

Neither is ours to write. They are listed so the -02 edit does not leave a
paragraph that forbids what the next section permits.

---

# What we did not write

- **Whether the mint-time refusal stays.** Warden refuses to sign a collapsing
  literal at `aat.Mint` and at `Deriver.Derive`. That is a producer-side choice
  about error quality — at mint the issuer is present and can be told what to
  write instead; at verify the holder has a signed token nobody can fix — and it
  needs no ratification from the draft. -02 should say what an enforcement point
  does, which is what §1.3 and §1.5 propose.

- **Anything about `hta` carrying an inadmissible number.** It cannot: §5.2's
  whole-payload canonicalization requirement forecloses it before the signature.
  The §5.2 note in §1.5 says so, and that is the whole of it.

- **A transition rule for -01 tokens.** Whether an enforcement point supporting
  both versions must accept a -01 token that a -02 verifier refuses is a
  question about -02's applicability statement, not about either of these
  findings. It is Q3 in `docs/O2-READINESS.md` and it is still open. Warden can
  implement either answer — it pins a spec identifier at bind and can branch on
  it — so we have no stake in which.
