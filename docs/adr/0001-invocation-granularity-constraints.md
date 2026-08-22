# ADR 0001 — Invocation-granularity constraints in AAT

Status: **Accepted** (warden design), **Proposed** (as a change to
`draft-niyikiza-oauth-attenuating-agent-tokens`)
Date: 2026-08-03
Supersedes: the `"*"` pseudo-argument placement recorded in ARCHITECTURE rev. 2 §2.4
Spec under discussion: `draft-niyikiza-oauth-attenuating-agent-tokens-01`,
N. A. Niyikiza (Tenuo), 15 June 2026. All bare "§" references are to that draft.

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
- Registration obligations are **unchanged from §3.5.1** — decidable, sound,
  deterministic `subsumes`, plus explicit cross-type rules — applied per constraint
  type rather than per argument key. §8.6's complexity-documentation requirement
  applies unchanged.
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

### The two types warden registers under it

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
- Enabling it is an explicit operator action (`extensions.invocation_constraints:
  true`). Enabling it is a statement that every enforcement point in the
  deployment is warden.
- Chains carrying it are marked in the transport binding — `_meta["dev.warden/spec"]`
  already carries a version string (ARCHITECTURE §3.1) and gains a profile
  suffix. This works only because warden defined its own transport; the signal does
  not generalize to any other binding, which is itself further evidence for the
  finding in §3.
- Every warden denial or permission involving these types cites
  `ext:dev.warden/budget` or `ext:dev.warden/rate` in the decision trace, so the
  M4 numbers separate cleanly into "draft-01 conformant" and "warden profile".

## 6. Suggested change to the draft (in preference order)

1. **Add `invocation_constraints` as specified in §4 above**, with the monotone
   set rule and the §3.5.1/§3.5.2 obligations carried over unchanged. This closes
   the granularity gap directly and costs the draft one member, one subsumption
   rule, and one step in §7.
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
  `invocation_constraints` member, implemented behind an operator flag that is off
  by default, with chains carrying it rejected when the flag is off.
- warden's contribution 2 (SPEC §2) is restated: not "we registered two extension
  types" but **"we identified a granularity gap in AAT's extension model and
  propose a mechanism to close it, with a working implementation and an
  evaluation."** This is a stronger claim than the one it replaces, and it is a
  claim about the standard rather than about our code.
- ARCHITECTURE §2.4, SPEC §2/§3.5/§5/§7, and ROADMAP M2 are updated to match.

## Consequences

- **Positive.** No silent divergence; conformance to draft-01 remains exact for
  everything outside the flagged profile. The finding is publishable on its own and
  is the strongest single result of the Phase 1 spec reading. It is also the part
  of warden most likely to be of direct use to the draft author.
- **Negative.** Budget and rate are non-interoperable until (or unless) the draft
  changes; anyone deploying them is deploying a warden profile. M4 must report
  conformant and profile numbers separately.
- **Open.** Whether the author agrees the gap is real. This ADR is written to be
  sendable to `niki@tenuo.ai` largely as-is, and to be liftable into the TCC as
  the "limitations of the underlying specification" section. Not sent — Igor's
  call.
