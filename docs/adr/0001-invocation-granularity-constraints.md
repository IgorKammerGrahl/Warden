# ADR 0001 — Invocation-granularity constraints in AAT

Status: **Accepted** (warden design). As a change to
`draft-niyikiza-oauth-attenuating-agent-tokens`: the **diagnosis in §3 is
confirmed by the draft author**; the **mechanism proposed in §4 is not adopted**.
See the Update below.
Date: 2026-08-03. Updated 2026-08-31 (author's response; the four defects
recorded against this ADR in `STATE.md` applied).
Supersedes: the `"*"` pseudo-argument placement recorded in ARCHITECTURE rev. 2 §2.4
Spec under discussion: `draft-niyikiza-oauth-attenuating-agent-tokens-01`,
N. A. Niyikiza (Tenuo), 15 June 2026. All bare "§" references are to that draft.

---

## Update, 2026-08-31 — the draft author's response

This ADR was sent to the draft author, who confirmed the central claim:

- The **argument-constraint registry (§3.5/§10.3) cannot host invocation-level
  controls.** The mechanism is indexed by argument name at every layer, and a
  cumulative control has no argument to be indexed by. §3 below is agreed.
- Cumulative controls **stay out of scope** for the core specification. §8.1.2
  already declares them unmitigated and points to rate limiting as a
  complementary control; that position does not change.
- **-02 will make the boundary explicit** and point to §8.10 (Approval Gates) as
  the shape such a control should take — a profile that says how the requirement
  is encoded, how it is preserved or attenuated during derivation, and what it
  is evaluated against — rather than an entry in the constraint-type registry.

What that settles and what it does not. It settles the diagnosis: the gap is
real, it is structural, and the registry is not where it gets closed. It does
**not** adopt the `invocation_constraints` member proposed in §4 — that remains
a proposal, and one the author has not accepted. §4's value after this response
is as a worked example of what a profile at that granularity has to define, and
the subsumption rule in it is the part most likely to survive into one.

The criticality mechanism proposed in §6 option 2 is untouched by the response
and is the broader of the two asks; §3's closing observation about the
silent-vanish hole stands unaddressed either way.

The rest of this ADR is unchanged from 2026-08-03 except where §3, §4 and §6 are
marked. Nothing was retro-fitted to agree with the reply.

---

## Context

warden enforces AAT delegation chains at the MCP tool-call layer. Two of the
controls it needs — a cumulative spend cap (`budget`) and a call-rate cap
(`rate`) — have no counterpart among the nine core constraint types in §3.4, and
none can be constructed from them. Both are cumulative properties of a *sequence*
of invocations under a delegation chain, not predicates over a single argument
value.

The draft anticipates extension: §3.5 establishes an IANA registry, and §3.5.1
imposes three obligations on every registration (a `subsumes` procedure that is
decidable, sound, and deterministic, plus exhaustive cross-type rules). warden's
initial design registered `dev.warden/budget` and `dev.warden/rate` under that
registry and placed each instance in a tool's constraint map under a reserved
pseudo-argument key `"*"`.

**That placement does not work.** The failure is mechanical, not stylistic, and it
is worth recording precisely, because the reason it fails generalizes: it is not a
mistake about where to put the constraint, but evidence that the draft has no
place to put it.

## 1. Why `"*"` denies every invocation

§3.3 puts an enforcement point into closed-world mode for any tool whose
constraint map is non-empty, with two symmetric rules:

> any argument not named in the constraint map MUST be rejected. A constrained
> argument that is absent from the invocation MUST also be rejected. […] This is a
> security property, not a configuration option.

§7 step 6b is the operational form of the second rule:

> For each argument name present in the constraint map, if that argument is absent
> from args, DENY (constrained argument MUST be present).

`"*"` is an argument name present in the constraint map. No invocation ever
carries an argument literally named `"*"`. Therefore **every invocation of a tool
carrying a `"*"` constraint is denied**, unconditionally, by a conformant
enforcement point. Not degraded, not unenforced — denied.

§7 step 4 p2 makes it worse rather than containable:

> if the parent's constraint map is non-empty, verify the child's constraint map
> contains exactly the same set of argument keys. If any key is added or removed,
> DENY.

So `"*"` cannot be introduced at one hop and dropped at the next. Once a budgeted
tool appears anywhere in a chain, the key is pinned into every descendant token,
and the whole subtree is dead for that tool.

The only way to make `"*"` function is for the enforcement point to special-case
the key out of the closed-world check in §7 step 6b — a silent divergence from the
normative algorithm. A warden-minted chain would then work against warden and deny
everything against any other conformant implementation. That forfeits the
independent-conformant-implementation property, which is the entire strategic
argument for building on the draft at all (ARCHITECTURE §2.3). A private
divergence that is invisible until interop is attempted is the worst available
outcome.

## 2. Why the alternative placements also fail — and fail in the same direction

Three other slots exist in draft-01. Each fails, and the *shape* of the failure is
the finding.

**(a) A top-level JWT claim** (e.g. `budget_max` alongside `del_depth`). §3.4:

> Enforcement points MUST ignore unrecognized top-level JWT claims; a token MUST
> NOT be rejected solely because it contains claims outside those defined in this
> specification.

A conformant peer therefore ignores the budget and permits the invocation. The
restriction vanishes silently.

**(b) A separate `authorization_details` entry with a different `type`.** §3.3:

> Enforcement points implementing this specification process only entries with
> type set to attenuating_agent_token and MUST ignore entries of other types.

Same outcome: silent vanish.

Both are precisely the failure mode §3.5.2 exists to forbid:

> An enforcement point that does not implement a registered extension constraint
> type MUST deny authorization rather than skip the constraint. […] Silently
> omitting that check would violate the attenuation guarantee.

**(c) Piggybacking on a real argument key.** The strongest-looking alternative:
attach the budget constraint to some argument the tool always receives, and have
its `check` predicate ignore the argument value and consult the counters instead.
This is conformant on the surface — the key is present, closed-world is satisfied,
subsumption is structural. It fails on four counts:

1. It requires every budgeted tool to have an argument that is *always* present.
   Tools that take no arguments cannot host it at all, and a tool whose constraint
   map is empty is in open-world mode, so introducing the key changes the tool's
   argument contract as a side effect of budgeting it.
2. §10.3.1 criterion 2 requires a registration's check predicate to be
   determinable from the argument value: "given any argument value, an independent
   implementer can determine without ambiguity whether the predicate returns true
   or false." A predicate whose result depends on hidden counter state and not on
   the value fails that criterion as written.
3. Key-set preservation (§7 step 4 p2) couples the budget's survival to an
   unrelated argument's constraint remaining in the map down the chain. A
   legitimate attenuation of that argument is now entangled with the budget.
4. The audit trace becomes a lie: a denial attributable to `tools.transfer.memo`
   is really a spend-cap denial. warden's decision-trace contribution (SPEC §2,
   contribution 3) depends on the trace naming the clause that actually fired.

## 3. The finding

The four failures share one cause, and it is not a warden design error:

> **AAT's extension model admits only argument-granularity constraints. Cumulative
> controls are invocation-granularity. The draft has no extension point at that
> granularity, and no extension point at any granularity whose absence of support
> a peer can detect.**

§3.4 defines a constraint as "a predicate over a tool argument value"; §3.5.1
defines `subsumes` over instances of a constraint type — that is, over argument
constraint instances; §7 evaluates constraints inside a per-argument loop.
Every layer of the mechanism is indexed by argument name. A control over a
sequence of invocations has no argument to be indexed by.

This explains an otherwise curious fact about the core vocabulary: nine constraint
types, covering scalars, ranges, sets, arrays, and boolean composition — and not
one cumulative control, despite budget and rate limiting being the two features
every deployed agent-guardrail product ships. It is not an oversight in the
vocabulary. There is nowhere in the model to put them.

**The draft knows this, and the finding is not that it does not.** §8.1.2 lists
*Actions within authorized argument constraints* among the threats AATs do not
mitigate, in terms that could hardly be plainer:

> They do not restrict which authorized invocations an agent chooses to make, in
> what order, or how many times. An agent that makes excessive or unintended use
> of its authorized tools within the bounds of its token is not detectable at the
> enforcement point. **Rate limiting, audit logging, and behavioral monitoring
> are complementary controls for this threat.**

So the omission is declared, and a reader who stops at §8.1.2 has no reason to
look further. The contribution of this ADR is one step past that sentence:

> **The extension registry the draft provides cannot host the complementary
> control §8.1.2 points to.** §3.5 exists precisely so that restrictions the core
> vocabulary cannot express can be added without a new revision, and §3.5.2 gives
> them a fail-closed guarantee no other part of the token has. Rate limiting is
> the named example of such a restriction. It is the one class the registry
> cannot take.

That is a claim about the shape of the extension model, not about the threat
model, and §8.1.2 does not answer it: pointing at rate limiting as a
complementary control is compatible with the control living anywhere — in the
proxy's configuration, in a sidecar, in the tool server. What it is not
compatible with is the assumption an implementer will actually make, which is
that the registry §3.5 advertises is where a missing restriction goes.

Two further observations, both about what is already in the model:

- **Enforcement-side state is not the novelty here.** §8.5 already requires an
  enforcement point to hold state across invocations — "enforcement points MUST
  implement stateful `jti` tracking for PoP JWTs" for irreversible operations —
  and declines, in the same section, to specify the storage backend or
  consistency model for it. A cumulative counter is the same kind of object under
  the same kind of deferral. The draft's verification model is already not purely
  stateless; what it lacks is a way for a *token* to say which state applies.
- **Nothing in §8.1.2 restores the fail-closed property.** Whether or not
  cumulative controls belong in the core, an issuer still has no way to mark any
  requirement as one a peer must understand or refuse. That is the observation
  below, and it is independent of the granularity question.

A second, sharper observation follows. §3.5.2's fail-closed rule gives draft-01 a
strong property: *an issuer's intended restriction can never be silently dropped
by a peer that does not implement it.* That property is complete for argument
constraints (unknown `constraint_type` ⇒ deny, §3.4/§8.8) and **has a hole
everywhere else**: unknown top-level claims MUST be ignored, unknown
`authorization_details` entry types MUST be ignored, and unknown *members inside*
the `attenuating_agent_token` entry are unspecified — in practice ignored, since
JSON decoders drop unknown fields by default. There is no way for an issuer to say
"this token carries a requirement you must understand or refuse." JWS solved this
in RFC 7515 §4.1.11 with the `crit` header parameter; AAT has no analogue.

## 4. Proposed mechanism (a change to the draft, not a use of it)

> **Nothing in this section is implemented.** It is a specification written *for*
> the draft, not a description of warden. The only code that exists for any of it
> is the refusal described in §5: `wardend` detects an `invocation_constraints`
> member and denies the chain. No type below is registered, no `check` runs, no
> counter exists, and the eval has no rows for any of it. Every MUST, MAY and
> obligation in this section states what a registration *would* have to satisfy —
> none of them describes behaviour that anything has.

Add an OPTIONAL `invocation_constraints` member to the
`attenuating_agent_token` entry, alongside `tools`:

```jsonc
{
  "type": "attenuating_agent_token",
  "tools": {
    "transfer_funds": { "amount": { "constraint_type": "range", "max": 5000 } }
  },
  "invocation_constraints": {
    "dev.warden/budget": { "max": 10000, "currency": "USD" },
    "dev.warden/rate":   { "max_calls": 50, "window_seconds": 3600 }
  }
}
```

- The member is an object whose **keys are registered invocation-constraint type
  names** and whose values are that type's instance object. The type name is the
  key, so a token carries at most one instance per type — this gives the set
  comparison a well-defined index, the role argument names play for `tools`.
- Instances are evaluated **once per invocation**, after the leaf capability check
  (§7 step 6b) and before PERMIT, independently of which tool is invoked.
- An absent `invocation_constraints` member means no invocation-level constraints,
  analogous to an empty constraint map meaning no argument restrictions.
- Registration obligations carry over from §3.5.1 — decidable, sound,
  deterministic `subsumes`, plus explicit cross-type rules — applied per constraint
  type rather than per argument key. §8.6's complexity-documentation requirement
  applies unchanged. **Two of them cannot be carried over verbatim, and saying
  "unchanged" would be a contradiction**; see immediately below.

### The two obligations that must be restated, and why "unchanged" will not do

Both §3.5.1's *Sound* property and §10.3.1's criterion 2 are quantified over
**argument values**. An invocation constraint has no argument value, so a
registration that claimed to satisfy them as written would be claiming something
with no referent. Relocating one and not the other leaves the contradiction in
place; both have to move, and they move the same way.

**§3.5.1 property 2 (Sound), as written:**

> if the procedure returns true for (C_parent, C_child), then for all argument
> values v: C_child.check(v) implies C_parent.check(v).

**Restated for an invocation-constraint type.** Let `S` range over the
enforcement point's counter states for the applicable counter (defined under
*Counter state* below), together with the invocation being decided:

> if `subsumes(C_child, C_parent)` returns true, then for every state `S`:
> `C_child.check(S)` implies `C_parent.check(S)`.

The conservative allowance is unchanged — the procedure MAY return false for
semantically subsuming pairs — and so is the prohibition: it MUST NOT return true
for a non-subsuming pair. The §4 table's *Sound* row is already an argument of
exactly this form (`spent + c ≤ Cd.max ≤ Cp.max` ⇒ the parent's predicate holds
*on the same state*), which is what makes the restatement a clarification of
what was meant rather than a weakening.

**§10.3.1 criterion 2, as written:**

> The check predicate is fully specified: given any argument value, an
> independent implementer can determine without ambiguity whether the predicate
> returns true or false.

**Restated:** given any state of the applicable counter and any invocation, an
independent implementer can determine without ambiguity whether the predicate
returns true or false. The registration MUST therefore also specify what the
counter counts, how the invocation contributes to it (for `dev.warden/budget`,
the per-tool cost table, which comes from the enforcement point and never from
the caller), and which counter is the applicable one. Absent those, the predicate
is not determinable and the registration fails the criterion — which is the
correct outcome, and the reason §2(c) rejected piggybacking a stateful predicate
onto an argument key: there the criterion could not be met at all, because the
hidden state was hidden by construction.

Note what does *not* move. **Decidable** and **Deterministic** are unchanged: the
procedure is still an integer comparison over two token claims, consulting no
state, so it terminates and two implementations agree. **Only `check` is
stateful.** The restatement quantifies the soundness of a stateless procedure
over the states its predicate will later be evaluated in; it does not make
subsumption depend on state, and if it did, offline chain verification would be
gone.

### Counter state

> **This subsection is unimplemented and unreviewed design authored during a
> documentation pass (2026-08-31) — it is not a record of a decision taken while
> building warden.** The defects it was written to correct had been recorded
> against a "Counter state" section that had never existed: the ADR used the
> phrase "the applicable counter" four times without ever defining it. So this
> text is newer than the ADR around it, it was written in prose rather than
> arrived at in code, and no implementation has ever pushed back on it. In
> particular, **the lineage key in obligation 2 and the state-loss position below
> are assumed positions, not conclusions** — one author's pick among alternatives,
> untested. Nothing in warden implements any of it.

None of this is meaningful without saying which counter a `check` consults. The
obligations on an enforcement point implementing an invocation-constraint type:

1. **One counter per (chain lineage, constraint type) pair, and an invocation is
   charged against every ancestor carrying an instance of that type** — not
   against every ancestor. A token that carries no instance of the type has no
   counter of that type, and inventing one for it would charge spend to a link
   that never asked for a cap. The leaf's own instance is included. This is what
   makes a parent's cap binding on its descendants: a child may hold a tighter
   budget, but spending under the child still draws down the parent's.
2. **The lineage key is the ancestor token's `jti`**, not its holder key: two
   sibling tokens derived from one parent with the same `cnf` are two lineages
   under the parent's one counter, and a re-issued token with a fresh `jti` is
   deliberately a fresh counter, which is the only reason a cap is ever refilled.
   This inherits a known ambiguity and a registration must say so: §3.2 Table 1
   conditions `jti`'s lowercase rule on a predicate — "if it is a UUID" — that the
   draft never defines (`docs/ref/NOTES.md` #1), so two implementations can
   disagree about whether two `jti` values are the same key. For a replay cache
   that is a disagreement about whether a token was already seen; for a counter it
   is a disagreement about whether spend accumulates or splits in two.
3. **The charge is applied before PERMIT is returned**, and a `check` that
   cannot read its counter DENIES. This is §3.5.2's rule — an unimplementable
   constraint denies rather than skips — applied to the state rather than to the
   type.

**State loss, stated rather than solved.** warden's counters would be in memory,
snapshotted on a timer, with a staleness rule discarding counters older than the
oldest live token's `iat`. **That does not detect a crash between snapshots**:
every charge since the last snapshot is silently refunded on restart, and the
holder gets that much of its cap back. Nothing in the design notices; the refund
is indistinguishable from a cap that was never spent.

There are two honest positions and this ADR takes the first:

- **State the bound.** Spend may be over-permitted by up to one snapshot
  interval's worth of invocations per lineage, per unclean restart. An operator
  choosing a snapshot interval is choosing that bound, and it must be documented
  in the deployment guide as a number rather than left as a property of the
  implementation.
- **Charge durably before PERMIT.** Correct, and it puts a synchronous durable
  write in front of every authorized invocation — which is a latency and
  availability decision, not a spec question, and one nobody should make on this
  project's behalf.

Either way the counters are **local to one `wardend` process, and that is a
declared v1 non-goal, not a deferred feature.** In-memory counters are not
shared: two `wardend` instances fronting the same tool server enforce two
independent caps, so a holder with access to both gets `n × max`. A deployment
that runs more than one instance over one chain population MUST NOT enable the
mechanism. This is the same shape as §8.5's warning about un-audience-bound PoPs
being replayable across enforcement points, and it has the same remedy — shared
state — which the draft also declines to specify.
- Enforcement-point obligations are **unchanged from §3.5.2**: an unrecognized or
  unimplemented invocation-constraint type MUST deny, never skip.

### Subsumption rule (the part that is genuinely new)

For `invocation_constraints`, let `P` and `C` be the parent's and child's member
objects. The child subsumes the parent iff:

1. `keys(P) ⊆ keys(C)` — the child MUST carry every type the parent carries.
   Removing one drops a conjunct and widens authority. DENY on removal.
2. The child MAY carry types the parent does not. Adding a conjunct strictly
   narrows authority; this is ordinary attenuation.
3. For every `k ∈ keys(P)`, `subsumes_k(C[k], P[k])` per type `k`'s registered
   procedure.

**This is a different set rule from §7 step 4 p2, and deliberately so.** p2
requires *exact* key-set equality for arguments, and that requirement is correct
there: under closed-world semantics a parent constraining `{a, b}` permits only
invocations carrying exactly `{a, b}`, so a child constraining `{a}` would permit
invocations the parent *rejects* (missing `b`), and a child constraining
`{a, b, c}` would permit invocations the parent *rejects* (unknown `c`). Neither
is a subset; hence exact preservation.

Invocation constraints have no such coupling, because there is no caller-supplied
value whose presence is being adjudicated. They are pure conjuncts over
enforcement state, so monotone addition is sound and removal is not. Applying p2's
rule here would be actively harmful: it would forbid a child from *adding* a
tighter budget where the parent had none, which is exactly the delegation pattern
the feature exists to support.

### The two types the proposal would register

> Neither type exists. There is no registration, no `check`, no counter and no
> eval row for either of them — §5's last bullet says the same thing from the
> other side. The table is the registration such a proposal owes, written out so
> that the obligations above have something concrete to be checked against. An
> earlier revision of this heading read "the two types warden registers under
> it", which was false.

| | `dev.warden/budget` | `dev.warden/rate` |
|---|---|---|
| Members | `max` (integer, currency minor units), `currency` (ISO 4217) | `max_calls` (integer), `window_seconds` (integer) |
| `check` | cumulative spend for the applicable counter + this invocation's cost ≤ `max`; cost comes from the enforcement point's configured per-tool cost table, never from the caller | calls in the trailing `window_seconds` for the applicable counter < `max_calls` |
| `subsumes(Cd, Cp)` | `Cd.currency == Cp.currency ∧ Cd.max ≤ Cp.max`. Differing currency ⇒ false: FX at verification time is neither deterministic nor offline | `Cd.max_calls ≤ Cp.max_calls ∧ Cd.window_seconds ≥ Cp.window_seconds`; every other combination ⇒ false, conservatively |
| Decidable | O(1) integer comparison | O(1) integer comparison |
| Sound | `spent + c ≤ Cd.max ≤ Cp.max` ⇒ parent's predicate holds on the same state | no more calls over a window at least as long ⇒ parent's predicate holds |
| Deterministic | integers in minor units; no floats, no locale | integers |
| Cross-type | none: parent `dev.warden/budget` accepts only child `dev.warden/budget`. Every pair with a core type is explicitly invalid — a stateless `range` substituted for a cumulative cap would silently drop the accumulation | as left |

Note that `subsumes` is **structural and offline** for both: it compares integers
in two tokens and consults nothing else. Chain verification therefore remains
fully offline and I4-checkable by a verifier holding no counters at all. Only
`check` is stateful. This is the property that makes cumulative controls
compatible with the draft's verification model, and it is the reason the proposal
is a placement change rather than a change to the attenuation algebra.

## 5. Interop consequence, and what warden does about it

A chain carrying `invocation_constraints` is **not interoperable with a
draft-01-only enforcement point.** Such a peer will not recognize the member and
will — per the JSON-decoder default and the absence of any rule requiring
otherwise — ignore it, permitting invocations that the issuer intended to cap.
This is the same silent-vanish failure as §2(a) and §2(b), and warden cannot fix
it from the outside: there is no signal in draft-01 that makes an unrecognized
requirement fatal to a peer.

warden's behavior, accordingly:

- The mechanism is **off by default**. With it disabled, `wardend` **rejects** any
  chain carrying an `invocation_constraints` member rather than ignoring it —
  the behavior we are asking peers to have.
- Enabling it would be an explicit operator action
  (`extensions.invocation_constraints: true`), and would be a statement that
  every enforcement point in the deployment is warden. **No such operator action
  exists today**: `proxy.Enforcer.InvocationConstraints` is a struct field with
  no `wardend` flag behind it, so in the shipped binary the gate is always on and
  a chain carrying the member is always rejected. That is deliberate — there is
  nothing to enable, since nothing evaluates the member — and it is stated here
  because the bullet above otherwise reads as a description of a configurable
  feature.
- Chains carrying it are marked in the transport binding — `_meta["dev.warden/spec"]`
  already carries a version string (ARCHITECTURE §3.1) and gains a profile
  suffix. This works only because warden defined its own transport; the signal does
  not generalize to any other binding, which is itself further evidence for the
  finding in §3.
- Every warden denial or permission involving these types would cite
  `ext:dev.warden/budget` or `ext:dev.warden/rate` in the decision trace, so the
  M4 numbers separate cleanly into "draft-01 conformant" and "warden profile".
  The split exists in the eval and is reported; the two extension types have no
  rows in it, because they have no implementation.

## 6. Suggested change to the draft (in preference order)

1. **Add `invocation_constraints` as specified in §4 above**, with the monotone
   set rule and the §3.5.1/§3.5.2 obligations carried over — restated over
   counter states where §4 says they must be. This closes the granularity gap
   directly and costs the draft one member, one subsumption rule, and one step in
   §7. *(Not adopted: the author's response keeps cumulative controls out of the
   core and points to a §8.10-shaped profile instead. §4 stands as a worked
   example of what such a profile has to define.)*
2. **Failing that, add a criticality mechanism** — the smaller and more general
   change. A member (or JWS header parameter, following RFC 7515 §4.1.11 `crit`)
   listing extension names that an enforcement point MUST understand or DENY.
   This does not give cumulative controls a home, but it converts every
   silent-vanish path in §2 into a detectable failure, which restores §3.5.2's
   guarantee across the whole token rather than only within
   `tools`. Deployments could then carry invocation-level controls in a top-level
   claim without the restriction evaporating at a peer.

Option 2 is worth raising even if option 1 is adopted: the hole it closes is
wider than budget and rate, and the precedent (X.509 critical extensions, JWS
`crit`) is well established.

## Decision

- The `"*"` pseudo-argument placement is **withdrawn**. warden will not
  special-case the closed-world check in §7 step 6b, and will not diverge silently
  from the verification algorithm anywhere.
- `dev.warden/budget` and `dev.warden/rate` move to a proposed
  `invocation_constraints` member. The intended shape was an operator flag, off by
  default, with chains carrying the member rejected while it is off; **only the
  rejection was ever built** — there is no flag and nothing to enable (§5). This
  bullet previously read "implemented behind an operator flag", which described a
  configurable feature that does not exist.
- warden's contribution 2 (SPEC §2) is restated: not "we registered two extension
  types" but **"we identified a granularity gap in AAT's extension model and
  propose a mechanism to close it."** This is a stronger claim than the one it
  replaces, and it is a claim about the standard rather than about our code.

  **The claim stops there.** `dev.warden/budget` and `dev.warden/rate` are
  specified in §4 and **not implemented**: there is no counter store, no cost
  table, no evaluation of the member's contents, and nothing in `eval/` measures
  them. The only code is the *refusal* — `internal/proxy/enforce.go` detects the
  member during the payload pass and denies the chain at §3.2 stage 5, and the
  §3.1 profile label is refused alongside it. An earlier revision of this bullet
  claimed "a working implementation and an evaluation" and that was wrong; it is
  corrected here rather than quietly deleted, because the overclaim is the kind a
  reader is entitled to see retracted. The eval's T4 threat class has no denial
  cases for the same reason, and `eval/results/summary.md` prints
  `unbounded-repetition` as a documented non-block rather than hiding it.
- ARCHITECTURE §2.4, SPEC §2/§3.5/§5/§7, and ROADMAP M2 are updated to match.

## Consequences

- **Positive.** No silent divergence; conformance to draft-01 remains exact for
  everything outside the flagged profile. The finding is publishable on its own and
  is the strongest single result of the Phase 1 spec reading. It is also the part
  of warden most likely to be of direct use to the draft author.
- **Negative.** Budget and rate are non-interoperable until (or unless) the draft
  changes; anyone deploying them is deploying a warden profile. M4 must report
  conformant and profile numbers separately.
- **Resolved.** Whether the author agrees the gap is real. He does; see the
  Update at the top. This was the open question when the ADR was written, and it
  was the only one the ADR could not answer for itself.
- **Still open.** Whether a §8.10-shaped profile is a *sufficient* home for
  cumulative controls, or only a permitted one. A profile that each deployment
  writes for itself gives interoperating peers nothing to agree on, which is the
  same silent-vanish exposure as §2(a) and §2(b) wearing a different label — and
  §6 option 2's criticality mechanism is what would make the divergence
  detectable. Nothing in the response addresses it.
