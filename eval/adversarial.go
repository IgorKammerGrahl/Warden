package main

import (
	"encoding/json"
	"strings"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/proxy"
)

// The adversarial corpus.
//
// Chains here are built by (*chain).forge and (*chain).forgeRoot, which sign a
// claim map directly: no aat.Deriver, no aat.Mint, no invariant between the
// mutation and the wire. Where a case needs a legitimate chain to attack, that
// prefix is built with derive and asserted with must() — a refusal there is a
// bug in this file, not a finding about warden.
//
// Profile "conformant" means the expected outcome follows from draft-01 alone.
// Profile "warden" means it follows from a decision recorded in ADR 0001 or in
// docs/ref/NOTES.md, and a conformant implementation could differ.
//
// WantRef is the FINEST CITATION THAT IS TRUE OF THIS INPUT — the clause an
// operator reading the audit trace should be shown, chosen from the draft (or
// from ARCHITECTURE/SPEC for a warden-profile case), never from what the
// implementation happens to emit. Where the two differ the run reports a ref
// mismatch, and that is the intended reading: a block attributed to the wrong
// clause is a finding about the decision trace, which is SPEC contribution 3,
// not a block to be counted and forgotten. No case is left at the "§7" stage
// floor, because a floor value would make the oracle accept any denial at all.

// Grants used as attack bases.
const (
	advTools    = `{"echo":{},"read_file":{}}`
	advEcho     = `{"echo":{}}`
	advWide     = `{"echo":{},"read_file":{},"write_file":{}}`
	advExact    = `{"echo":{"text":{"constraint_type":"exact","value":"ping"}}}`
	advOneOf    = `{"echo":{"text":{"constraint_type":"one_of","values":["ping","pong"]}}}`
	advRangeLow = `{"search":{"limit":{"constraint_type":"range","min":1,"max":10}}}`
	advRangeHi  = `{"search":{"limit":{"constraint_type":"range","min":1,"max":100}}}`
)

const (
	goodArgs = `{"text":"hello"}`
	pingArgs = `{"text":"ping"}`
)

func adversarialCases(w *world) []Case {
	var out []Case
	add := func(c Case) { out = append(out, c) }

	// A one-hop legitimate chain, reused as the thing forgeries extend.
	base := func() *chain { return newChain(w, advTools, 8).derive(advEcho, nil).must() }

	// ---------------------------------------------------------------- bind
	//
	// The transport binding is warden's (ARCHITECTURE §3.1), so these are
	// warden-profile: draft-01 defines no MCP binding and another
	// implementation could carry the chain somewhere else entirely. What is
	// conformant is that none of them reaches an authorization decision.

	nometa := base()
	add(Case{Name: "bind-no-meta", Class: "T1", Profile: "warden",
		Tool: "echo", Depth: nometa.depth(), WantRef: "ARCHITECTURE §3.1",
		Note: "no params._meta at all: there is no unauthenticated path and no bearer fallback",
	}.finish(nil, goodArgs))

	add(attack(Case{Name: "bind-no-chain", Class: "T1", Profile: "warden",
		Tool: "echo", WantRef: "ARCHITECTURE §3.1",
		Meta: meta("", base().pop("echo", json.RawMessage(goodArgs)), proxy.SpecVersion),
	}, base(), goodArgs))

	add(attack(Case{Name: "bind-no-pop", Class: "T5", Invariant: "I6", Profile: "warden",
		Tool: "echo", WantRef: "ARCHITECTURE §3.1",
		Note: "a chain with no proof of possession is a bearer token; §5.1 forbids that reading",
		Meta: meta(string(mustMarshal(base().raws)), "", proxy.SpecVersion),
	}, base(), goodArgs))

	add(attack(Case{Name: "bind-empty-chain", Class: "T6", Profile: "warden",
		Tool: "echo", WantRef: "ARCHITECTURE §3.1",
		Note: "§7 step 1 is the conformant citation; warden's binding refuses one stage earlier",
		Meta: meta(`[]`, base().pop("echo", json.RawMessage(goodArgs)), proxy.SpecVersion),
	}, base(), goodArgs))

	add(attack(Case{Name: "bind-chain-not-an-array", Class: "T6", Profile: "warden",
		Tool: "echo", WantRef: "ARCHITECTURE §3.1",
		Note: "a delimiter-joined chain, which §3.1 forbids: the split-mismatch bug as a denial",
		Meta: meta(string(mustMarshal(strings.Join(base().raws, " "))),
			base().pop("echo", json.RawMessage(goodArgs)), proxy.SpecVersion),
	}, base(), goodArgs))

	add(attack(Case{Name: "bind-spec-version-mismatch", Class: "T6", Profile: "warden",
		Tool: "echo", WantRef: "ARCHITECTURE §3.1",
		Meta: meta(string(mustMarshal(base().raws)),
			base().pop("echo", json.RawMessage(goodArgs)),
			"draft-niyikiza-oauth-attenuating-agent-tokens-02"),
	}, base(), goodArgs))

	add(attack(Case{Name: "bind-extension-profile-label", Class: "T6", Profile: "warden",
		Tool: "echo", WantRef: "ARCHITECTURE §3.1",
		Note: "§3.1's +dev.warden.invocation_constraints profile label, honestly declared and " +
			"still refused because the extension is off (SPEC §5.3)",
		Meta: meta(string(mustMarshal(base().raws)),
			base().pop("echo", json.RawMessage(goodArgs)),
			proxy.SpecVersion+"+dev.warden.invocation_constraints"),
	}, base(), goodArgs))

	// ------------------------------------------------- ambiguous numbers
	//
	// NOTES #7. Both halves of the 2^53 collision, and they do not come out
	// the same way.

	add(attack(Case{Name: "jcs-ambiguous-argument", Class: "T3", Profile: "warden",
		Tool: "echo", WantRef: "§7 step 7f",
		Note: "9007199254740993 shares its RFC 8785 canonical form with 9007199254740992, so " +
			"step 7f cannot tell the PoP's value from the forwarded one",
	}, newChain(w, advTools, 8).derive(advEcho, nil).must(), `{"text":"hi","n":9007199254740993}`))

	// The other half, and it is NOT blocked. A constraint literal above 2^53
	// is refused at mint (aat.Deriver), deliberately not at verify — so a
	// token minted by some other issuer carrying one arrives, collapses, and
	// authorizes a value it never named.
	add(attack(Case{Name: "jcs-ambiguous-constraint-literal", Class: "T2", Invariant: "I4",
		Profile: "warden", Expect: "permit",
		Tool: "echo",
		Note: "KNOWN NON-BLOCK (NOTES #7): the token grants n == 9007199254740993; the call " +
			"passes 9007199254740992 and is permitted, because both collapse to the same float64. " +
			"warden refuses this at mint, not at verify.",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		// text is granted too: §3.3 closed-world refuses an argument key the
		// grant does not name, and that denial would land before the collapse
		// this case is about.
		m["authorization_details"] = details(
			`{"echo":{"text":{"constraint_type":"exact","value":"hi"},` +
				`"n":{"constraint_type":"exact","value":9007199254740993}}}`)
	}, forgeOpts{}), `{"text":"hi","n":9007199254740992}`))

	// ------------------------------------------------------------- the root

	rogue := newWorld(w.now)
	add(attack(Case{Name: "root-not-anchored", Class: "T6", Invariant: "I1",
		Tool: "echo", WantRef: "§7 steps 3a-3b, I1",
		Note: "a well-formed chain under an issuer key the deployment does not trust",
	}, newChain(rogue, advTools, 8).derive(advEcho, nil).must(), goodArgs))

	add(attack(Case{Name: "root-carries-par_hash", Class: "T2", Invariant: "I5",
		Tool: "echo", WantRef: "§7 step 3d",
		Note: "§3.2: par_hash MUST be absent at del_depth 0; aat.Mint refuses to produce this",
	}, forgeRoot(w, advTools, 8, func(m map[string]any) {
		// Well-formed base64url-nopad on purpose. A malformed value would ALSO
		// fail Table 1's shape rule, which Parse reaches first and cites as 3b,
		// and the case would then be measuring two defects at once. Presence on
		// a root is the one under test; the shape rule has its own unit test
		// (aat_test.go, "par_hash not base64url").
		m["par_hash"] = strings.Repeat("A", 43)
	}, forgeOpts{}), goodArgs))

	add(attack(Case{Name: "root-nonzero-del_depth", Class: "T2", Invariant: "I2",
		Tool: "echo", WantRef: "§7 step 3c",
	}, forgeRoot(w, advTools, 8, func(m map[string]any) { m["del_depth"] = 3 }, forgeOpts{}), goodArgs))

	add(attack(Case{Name: "root-expired", Class: "T5", Invariant: "I3",
		Tool: "echo", WantRef: "§7 step 3e, I3",
	}, newRoot(w, advTools, 8, func(c *aat.Claims) {
		c.IssuedAt, c.Expires = w.now-7200, w.now-3600
	}), goodArgs))

	add(attack(Case{Name: "root-lifetime-over-max", Class: "T5", Invariant: "I3",
		Tool: "echo", WantRef: "§7 step 3h, I3",
		Note: "§4.4 MAX_TOKEN_LIFETIME, 90 days by default in wardend",
	}, newRoot(w, advTools, 8, func(c *aat.Claims) {
		c.Expires = c.IssuedAt + 365*24*3600
	}), goodArgs))

	add(attack(Case{Name: "root-ceiling-over-deployment-max", Class: "T2", Invariant: "I2",
		Tool: "echo", WantRef: "§7 step 3i, I2",
	}, newRoot(w, advTools, 8, func(c *aat.Claims) { c.MaxDelegationDepth = 20 }), goodArgs))

	add(attack(Case{Name: "root-issuer-not-a-uri", Class: "T6",
		Tool: "echo", WantRef: "§7 step 3k",
	}, newRoot(w, advTools, 8, func(c *aat.Claims) { c.Issuer = "acme-issuer" }), goodArgs))

	// --------------------------------------------------------------- I1

	fp, fk := keypair()
	fpURI, err := aat.NewJWK(fp).ThumbprintURI()
	if err != nil {
		panic(err)
	}
	add(attack(Case{Name: "i1-issuer-is-attackers-own-key", Class: "T2", Invariant: "I1",
		Tool: "echo", WantRef: "§7 step 4c, I1",
		Note: "self-issued delegation: the child is signed by the parent's holder, as step 4b " +
			"requires, and names a different key as its issuer. Signed by the parent on purpose: " +
			"a foreign signature would die at 4b and never reach the iss check, which is the " +
			"case below",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) { m["iss"] = fpURI },
		forgeOpts{}), goodArgs))

	add(attack(Case{Name: "i1-signature-by-foreign-key", Class: "T2", Invariant: "I1",
		Tool: "echo", WantRef: "§7 steps 4a-4b, I1",
		Note: "iss names the parent holder correctly; the signature does not come from it",
	}, newChain(w, advTools, 8).forge(nil, forgeOpts{signer: fk}), goodArgs))

	// --------------------------------------------------------------- I2

	add(attack(Case{Name: "i2-depth-not-incremented", Class: "T2", Invariant: "I2",
		Tool: "echo", WantRef: "§7 step 4d, I2",
		Note: "delegating without spending a delegation: an unbounded chain at constant depth",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) { m["del_depth"] = 0 },
		forgeOpts{}), goodArgs))

	add(attack(Case{Name: "i2-depth-skipped", Class: "T2", Invariant: "I2",
		Tool: "echo", WantRef: "§7 step 4d, I2",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) { m["del_depth"] = 3 },
		forgeOpts{}), goodArgs))

	add(attack(Case{Name: "i2-ceiling-raised", Class: "T2", Invariant: "I2",
		Tool: "echo", WantRef: "§7 step 4g, I2",
		Note: "the child grants itself more delegation headroom than its parent had",
	}, newChain(w, advTools, 4).forge(func(m map[string]any) { m["del_max_depth"] = 8 },
		forgeOpts{}), goodArgs))

	add(attack(Case{Name: "i2-terminal-parent-delegates", Class: "T2", Invariant: "I2",
		Tool: "echo", WantRef: "§7 step 4e, I2",
		Note: "§4.3: del_depth == del_max_depth is terminal; aat.Deriver refuses to mint this",
	}, newChain(w, advTools, 1).derive(advEcho, func(d *aat.Derivation) { d.MaxDelegationDepth = 1 }).
		must().forge(nil, forgeOpts{}), goodArgs))

	over := newChain(w, advTools, 8)
	for i := 0; i < 9; i++ {
		over = over.forge(nil, forgeOpts{})
	}
	add(attack(Case{Name: "i2-chain-beyond-deployment-max", Class: "T2", Invariant: "I2",
		Tool: "echo", WantRef: "§7 step 4e, I2",
		Note: "ten tokens against MaxDelegationDepth 8. §7 step 5's own length check is " +
			"unreachable: 4d forces del_depth to track position, so 4e/4f always fire first.",
	}, over, goodArgs))

	// --------------------------------------------------------------- I3

	add(attack(Case{Name: "i3-expiry-extended", Class: "T5", Invariant: "I3",
		Tool: "echo", WantRef: "§7 step 4h, I3",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) { m["exp"] = w.now + 86400 },
		forgeOpts{}), goodArgs))

	add(attack(Case{Name: "i3-iat-backdated", Class: "T5", Invariant: "I3",
		Tool: "echo", WantRef: "§7 step 4j, I3",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) { m["iat"] = w.now - 100000 },
		forgeOpts{}), goodArgs))

	add(attack(Case{Name: "i3-leaf-already-expired", Class: "T5", Invariant: "I3",
		Tool: "echo", WantRef: "§7 step 4i, I3",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["iat"], m["exp"] = w.now-7200, w.now-3600
	}, forgeOpts{}), goodArgs))

	// --------------------------------------------------------------- I4

	add(attack(Case{Name: "i4-tool-set-widened", Class: "T2", Invariant: "I4",
		Tool: "write_file", WantRef: "§7 step 4p1, I4",
		Note: "the child grants itself a tool the parent never held",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(advWide)
	}, forgeOpts{}), `{"path":"/tmp/x","content":"y"}`))

	add(attack(Case{Name: "i4-constraint-widened-exact-to-one_of", Class: "T2", Invariant: "I4",
		Tool: "echo", WantRef: "§4.5, §7 step 4p4, I4",
		Note: "parent exact -> derived one_of is not a permitted §4.5 pair; NOTES #5's " +
			"default-deny is what refuses it",
	}, newChain(w, advExact, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(advOneOf)
	}, forgeOpts{}), pingArgs))

	add(attack(Case{Name: "i4-range-widened", Class: "T2", Invariant: "I4",
		Tool: "search", WantRef: "§4.5, §7 step 4p4, I4",
	}, newChain(w, advRangeLow, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(advRangeHi)
	}, forgeOpts{}), `{"limit":90}`))

	add(attack(Case{Name: "i4-open-world-reintroduced", Class: "T2", Invariant: "I4",
		Tool: "echo", WantRef: "§7 step 4p2, I4",
		Note: "a closed-world grant becomes open-world again: every argument constraint dropped",
	}, newChain(w, advExact, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(advEcho)
	}, forgeOpts{}), `{"text":"anything"}`))

	add(attack(Case{Name: "i4-argument-key-added", Class: "T2", Invariant: "I4",
		Tool: "echo", WantRef: "§7 step 4p2, I4",
		Note: "under closed-world semantics an argument the parent never named is one the " +
			"parent could never have passed, so adding a key widens",
	}, newChain(w, advExact, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(
			`{"echo":{"text":{"constraint_type":"exact","value":"ping"},` +
				`"path":{"constraint_type":"wildcard"}}}`)
	}, forgeOpts{}), pingArgs))

	// --------------------------------------------------------------- I5

	add(attack(Case{Name: "i5-par_hash-points-elsewhere", Class: "T2", Invariant: "I5",
		Tool: "echo", WantRef: "§7 step 4q, I5",
		Note: "a well-formed par_hash over a real token that is not this child's parent. " +
			"A malformed one would be refused as a bad claim inside Parse and never reach 4q",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["par_hash"] = aat.ParentHash(newChain(w, advTools, 8).must().toks[0])
	}, forgeOpts{}), goodArgs))

	// Reparenting: a token that WAS validly derived, presented under a
	// different root. Everything about it is genuine except which parent it
	// claims, and par_hash is the only check that notices.
	victim := newChain(w, advTools, 8).derive(advEcho, nil).must()
	other := newChain(w, advTools, 8).must()
	add(attack(Case{Name: "i5-derived-token-reparented", Class: "T2", Invariant: "I5",
		Tool: "echo", WantRef: "§7 step 4q, I5",
		Note: "both roots are anchored and share a holder key, so I1 through I4 all pass; " +
			"only the parent hash disagrees",
	}, victim.reparent(other), goodArgs))

	add(attack(Case{Name: "i5-par_hash-omitted-on-derived", Class: "T2", Invariant: "I5",
		Tool: "echo", WantRef: "§7 step 4b5",
		Note: "§3.2: par_hash is REQUIRED once del_depth > 0, and §7 step 4b5 is where the " +
			"algorithm checks it",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) { delete(m, "par_hash") },
		forgeOpts{}), goodArgs))

	// --------------------------------------------------------------- I6

	pk := base()
	add(attack(Case{Name: "i6-pop-signed-by-wrong-key", Class: "T1", Invariant: "I6",
		Tool: "echo", WantRef: "§7 steps 7a-7b, I6",
		Note: "the classic confused deputy: a chain someone else holds, presented with a " +
			"proof this party can actually produce",
		Meta: meta(string(mustMarshal(pk.raws)),
			pk.popAt(0, "echo", json.RawMessage(goodArgs), func(p *aat.PoPClaims) {
				p.TokenID = pk.toks[1].Claims.JTI
			}), proxy.SpecVersion),
	}, pk, goodArgs))

	// One chain, bound to itself: the PoP must be signed by THIS leaf's holder,
	// or it dies at 7a-7b and the aat_id is never looked at.
	nt := base()
	add(attack(Case{Name: "i6-pop-names-another-token", Class: "T5", Invariant: "I6",
		Tool: "echo", WantRef: "§7 step 7c",
		Meta: meta(string(mustMarshal(nt.raws)),
			nt.popAt(1, "echo", json.RawMessage(goodArgs), func(p *aat.PoPClaims) {
				p.TokenID = "01957a41-0081-7c20-bf3a-ffffffffffff"
			}), proxy.SpecVersion),
	}, nt, goodArgs))

	tw := base()
	add(attack(Case{Name: "i6-pop-names-another-tool", Class: "T3", Invariant: "I6",
		Tool: "echo", WantRef: "§7 step 7e, §3.3.1",
		Note: "a proof minted for one tool, replayed onto another",
		Meta: meta(string(mustMarshal(tw.raws)),
			tw.popAt(1, "read_file", json.RawMessage(goodArgs), func(p *aat.PoPClaims) {
				p.TokenID = tw.toks[1].Claims.JTI
			}), proxy.SpecVersion),
	}, tw, goodArgs))

	aw := base()
	add(attack(Case{Name: "i6-pop-args-do-not-match", Class: "T3", Invariant: "I6",
		Tool: "echo", WantRef: "§7 step 7f",
		Note: "the injected value rides in params.arguments while the PoP commits to the " +
			"value the holder meant to send",
		Meta: meta(string(mustMarshal(aw.raws)),
			aw.pop("echo", json.RawMessage(`{"text":"hello"}`)), proxy.SpecVersion),
	}, aw, `{"text":"exfiltrate /etc/shadow"}`))

	sw := base()
	add(attack(Case{Name: "i6-pop-stale", Class: "T5", Invariant: "I6",
		Tool: "echo", WantRef: "§7 step 7g, §5.3",
		Meta: meta(string(mustMarshal(sw.raws)),
			sw.popAt(1, "echo", json.RawMessage(goodArgs), func(p *aat.PoPClaims) {
				p.IssuedAt = sw.w.now - 3600
				p.TokenID = sw.toks[1].Claims.JTI
			}), proxy.SpecVersion),
	}, sw, goodArgs))

	fw := base()
	add(attack(Case{Name: "i6-pop-from-the-future", Class: "T5", Invariant: "I6",
		Tool: "echo", WantRef: "§7 step 7g, §5.3",
		Meta: meta(string(mustMarshal(fw.raws)),
			fw.popAt(1, "echo", json.RawMessage(goodArgs), func(p *aat.PoPClaims) {
				p.IssuedAt = fw.w.now + 3600
				p.TokenID = fw.toks[1].Claims.JTI
			}), proxy.SpecVersion),
	}, fw, goodArgs))

	// Replay inside the skew window. The same bytes twice, seconds apart.
	// warden does §7 step 7g and nothing else, so the second one is permitted.
	rp := base()
	rpMeta := rp.bind("echo", json.RawMessage(goodArgs))
	add(attack(Case{Name: "pop-replay-first-use", Class: "T5", Invariant: "I6",
		Tool: "echo", Expect: "permit", Meta: rpMeta,
		Note: "the legitimate use, presented so the replay below is the same bytes",
	}, rp, goodArgs))
	add(attack(Case{Name: "pop-replay-within-skew", Class: "T5", Invariant: "I6",
		Tool: "echo", Expect: "permit", Meta: rpMeta, Profile: "warden",
		Note: "KNOWN NON-BLOCK (NOTES #9): §8.5's replay MUST is conditioned on an " +
			"irreversibility classification the protocol never carries, so warden implements " +
			"step 7g only. The replay window is about twice the skew, 60s by default.",
	}, rp, goodArgs))

	// -------------------------------------------- prefix presentation, #6

	// A three-token chain whose leaf is the most attenuated token in it. The
	// attacker holds that leaf and truncates the chain to the prefix ending at
	// the wider intermediate token, which is a structurally valid chain under
	// §7 in its own right. aat_id is set to the prefix's leaf so nothing but
	// the signature is wrong.
	full := newChain(w, advWide, 8).derive(advTools, nil).derive(advEcho, nil).must()
	pre := full.truncate(2)
	add(attack(Case{Name: "prefix-presentation-escalates", Class: "T2", Invariant: "I6",
		Tool: "read_file", WantRef: "§7 steps 7a-7b, I6",
		Note: "NOTES #6: every prefix of a valid chain is a valid chain, so §7 steps 1-6 " +
			"pass and the prefix's leaf grants read_file. Only proof of possession refuses.",
		Meta: meta(string(mustMarshal(pre.raws)),
			full.popAt(2, "read_file", json.RawMessage(`{"path":"/etc/shadow"}`),
				func(p *aat.PoPClaims) { p.TokenID = pre.toks[1].Claims.JTI }),
			proxy.SpecVersion),
	}, pre, `{"path":"/etc/shadow"}`))

	// ------------------------------------------- algorithm confusion, §8.13

	add(attack(Case{Name: "alg-none-on-leaf", Class: "T6", Invariant: "I1",
		Tool: "echo", WantRef: "§7 steps 4a-4b, I1",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(advWide)
	}, forgeOpts{alg: "none"}), goodArgs))

	add(attack(Case{Name: "alg-hs256-under-parent-public-key", Class: "T6", Invariant: "I1",
		Tool: "echo", WantRef: "§7 steps 4a-4b, I1",
		Note: "§8.13: the signing input MACed under the Ed25519 public key the verifier " +
			"would otherwise verify against",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(advWide)
	}, forgeOpts{alg: "HS256"}), goodArgs))

	add(attack(Case{Name: "alg-none-on-root", Class: "T6", Invariant: "I1",
		Tool: "echo", WantRef: "§7 steps 3a-3b, I1",
	}, forgeRoot(w, advWide, 8, nil, forgeOpts{alg: "none"}), goodArgs))

	// ------------------------------------- out of authority, §7 step 6a/6b

	add(attack(Case{Name: "tool-not-granted", Class: "T3",
		Tool: "read_file", WantRef: "§7 step 6b",
		Note: "the leaf grants echo only; the injected instruction asks for a file",
	}, newChain(w, advTools, 8).derive(advEcho, nil).must(), `{"path":"/etc/shadow"}`))

	add(attack(Case{Name: "argument-violates-constraint", Class: "T3",
		Tool: "echo", WantRef: "§3.4 exact",
		Note: "step 6b is the step; the citation an operator needs is the constraint type " +
			"that refused, so the finest true ref is §3.4's exact",
	}, newChain(w, advOneOf, 8).derive(advExact, nil).must(), `{"text":"pong"}`))

	add(attack(Case{Name: "undeclared-argument", Class: "T3",
		Tool: "echo", WantRef: "§7 step 6b, §3.3 closed-world",
		Note: "an argument the closed-world constraint map never names, smuggled alongside " +
			"one it does",
	}, newChain(w, advExact, 8).derive(advExact, nil).must(),
		`{"text":"ping","path":"/etc/shadow"}`))

	// The same denial with no id: nothing comes back either way, so the audit
	// record is the only place the decision is observable.
	add(attack(Case{Name: "notification-bypass", Class: "T3",
		Tool: "read_file", WantRef: "§7 step 6b", Notify: true,
		Note: "tools/call as a JSON-RPC notification. A proxy that only enforces on the " +
			"response path would forward this unchecked.",
	}, newChain(w, advTools, 8).derive(advEcho, nil).must(), `{"path":"/etc/shadow"}`))

	// ------------------------------- constraint vocabulary, §3.5.2 fail-closed

	add(attack(Case{Name: "unknown-constraint-type", Class: "T2", Invariant: "I4",
		Tool: "echo", WantRef: "§3.5.2",
		Note: "§3.5.2: an enforcement point that does not understand a constraint type MUST " +
			"deny. Ignoring it would drop a restriction the issuer wrote down.",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(
			`{"echo":{"text":{"constraint_type":"regex","pattern":"^p"}}}`)
	}, forgeOpts{}), pingArgs))

	add(attack(Case{Name: "unrecognized-member-in-constraint", Class: "T2", Invariant: "I4",
		Profile: "warden", Tool: "echo", WantRef: "§3.4",
		Note: "NOTES #3: a recognized type carrying a member Table 2 does not define. warden " +
			"rejects; a lenient implementation would ignore the member and widen the grant.",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(
			`{"echo":{"text":{"constraint_type":"exact","value":"ping","case_sensitive":false}}}`)
	}, forgeOpts{}), pingArgs))

	add(attack(Case{Name: "empty-constraints-array", Class: "T2", Invariant: "I4",
		Profile: "warden", Tool: "echo", WantRef: "§3.4",
		Note: "NOTES #2: all/any with zero clauses. warden rejects at parse; the draft does " +
			"not say. This is an interop divergence, not a security one.",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(
			`{"echo":{"text":{"constraint_type":"all","constraints":[]}}}`)
	}, forgeOpts{}), pingArgs))

	add(attack(Case{Name: "over-deep-constraint-tree", Class: "T2", Invariant: "I4",
		Tool: "echo", WantRef: "§3.4 MAX_CONSTRAINT_DEPTH",
		Note: "§7 step 4o applies the §4.3 limit of 32: a nesting bomb that would otherwise " +
			"be unbounded recursion in Subsumes",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["authorization_details"] = details(`{"echo":{"text":` + nestedAll(40) + `}}`)
	}, forgeOpts{}), pingArgs))

	// ------------------------------------------- the extension gate, §2.4

	add(attack(Case{Name: "invocation-constraints-member", Class: "T2",
		Profile: "warden", Tool: "echo", WantRef: "ARCHITECTURE §2.4",
		Note: "SPEC §5.3: with the extension off, wardend rejects a chain carrying the " +
			"member rather than ignoring it — ignoring it would drop a restriction",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		// Sibling to "tools" inside the attenuating_agent_token entry, which is
		// where ARCHITECTURE §2.4 puts it. At the top level of the claim set it
		// is an unrecognized claim, and §3.2 says to ignore those.
		m["authorization_details"] = []json.RawMessage{json.RawMessage(
			`{"type":"attenuating_agent_token","tools":` + advTools +
				`,"invocation_constraints":{"max_invocations":1}}`)}
	}, forgeOpts{}), goodArgs))

	// -------------------------------------------- chain shape, §7 step 2

	add(attack(Case{Name: "chain-repeats-a-token", Class: "T6",
		Tool: "echo", WantRef: "§7 step 2c, cycle detection",
	}, base().repeatLeaf(), goodArgs))

	add(attack(Case{Name: "oversize-token", Class: "T6",
		Tool: "echo", WantRef: "§7 step 2a, §4.3.1",
		Note: "§4.3.1 MAX_TOKEN_SIZE, 64 KiB: padding in an unrecognized claim, which §3.2 " +
			"otherwise says to ignore",
	}, newChain(w, advTools, 8).forge(func(m map[string]any) {
		m["pad"] = strings.Repeat("A", 70000)
	}, forgeOpts{}), goodArgs))

	// ---------------------------------------------------- budget abuse, T4

	add(attack(Case{Name: "unbounded-repetition", Class: "T4",
		Tool: "echo", Expect: "permit", Profile: "warden",
		Note: "KNOWN NON-BLOCK: warden has no budget or rate counters (M2b deferred), so a " +
			"holder may invoke a granted tool without limit. T4 is unmitigated by design " +
			"today, and no §3.4 core constraint type expresses a call budget.",
	}, base(), goodArgs))

	return out
}

// nestedAll builds an all-constraint nested n deep, for the depth limit.
func nestedAll(n int) string {
	s := `{"constraint_type":"exact","value":"ping"}`
	for i := 0; i < n; i++ {
		s = `{"constraint_type":"all","constraints":[` + s + `]}`
	}
	return s
}

// attack completes an adversarial case: it fills the defaults, records the
// depth, and binds the chain unless the case supplied its own _meta.
func attack(k Case, c *chain, args string) Case {
	c.must()
	k.Args = json.RawMessage(args)
	k.Depth = c.depth()
	return k.finish(c, args)
}

func (k Case) finish(c *chain, args string) Case {
	k.Corpus = "adversarial"
	if k.Expect == "" {
		k.Expect = "deny"
	}
	if k.Profile == "" {
		k.Profile = "conformant"
	}
	k.Args = json.RawMessage(args)
	if k.Meta == nil && c != nil {
		k.Meta = c.bind(k.Tool, k.Args)
	}
	return k
}
