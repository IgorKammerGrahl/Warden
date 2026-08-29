package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/core"
	"github.com/igorkg/warden/internal/proxy"
)

// RootIssuer is the https issuer URI every root in both corpora names (§7 3k).
const RootIssuer = "https://issuer.eval.warden.dev"

var b64 = base64.RawURLEncoding

// Case is one invocation presented to a live wardend, plus what we expect.
//
// A Case is a wire message and a claim about it. It carries no reference to
// the builder that produced it, so the two corpora are indistinguishable to
// everything downstream of construction.
type Case struct {
	Name   string `json:"name"`
	Corpus string `json:"corpus"` // "benign" | "adversarial"
	// Class is the threat class (T1..T6) for adversarial cases and the
	// delegation pattern for benign ones.
	Class string `json:"class"`
	// Invariant is I1..I6 when the case attacks one, "" otherwise.
	Invariant string `json:"invariant,omitempty"`
	// Profile is "conformant" when the expected outcome follows from draft-01
	// alone, "warden" when it depends on a choice recorded in ADR 0001 or in
	// docs/ref/NOTES.md. See eval/METHOD.md.
	Profile string `json:"profile"`
	// Expect is what warden is documented to do: "permit" or "deny". An
	// adversarial case expecting "permit" is a known non-block, and Note says
	// why it is not blocked.
	Expect string `json:"expect"`
	// WantRef is the clause expected to fire. The report records the ref that
	// actually fired beside it: a denial for the wrong reason is not the same
	// result as a denial for the right one.
	WantRef string `json:"want_ref,omitempty"`
	Note    string `json:"note,omitempty"`

	Tool  string          `json:"tool"`
	Depth int             `json:"depth"`
	Args  json.RawMessage `json:"-"`
	Meta  json.RawMessage `json:"-"` // nil = no _meta member at all
	// WantSameScope is the chain.same_scope the audit record must carry.
	// Non-nil only where the scenario deliberately builds a same-scope link:
	// §6 makes those permits, so the field is checked on the permit rather
	// than turned into a third decision.
	WantSameScope []int `json:"want_same_scope,omitempty"`

	// Raw is the exact bytes to put on the wire, bypassing the tools/call
	// construction below. It exists for cases whose whole point is a message
	// shape a tools/call cannot express — a batch array, a params that is not
	// an object — which is the class the batch bypass came from.
	Raw json.RawMessage `json:"-"`

	// Notify sends the call as a JSON-RPC notification: no id, so no response
	// can be correlated. See the notification-bypass case.
	Notify bool `json:"notify"`

	// BuildErr is set when construction failed. For a benign case that is a
	// finding in itself — warden's own §6 minting refused a delegation the
	// corpus holds legitimate — so it is reported, never fatal.
	BuildErr string `json:"build_err,omitempty"`
}

// --- the trust domain ------------------------------------------------------

// world is the corpus's trust domain: one root issuer key shared by every
// scenario in both corpora.
//
// One key, not one per scenario, for a measurement reason. §7 step 3b tries
// each configured anchor until one verifies, so a sixty-key anchor set puts up
// to sixty Ed25519 verifications in front of every root and makes the anchor
// set a variable in a number that is meant to be about chain depth. The
// unanchored-root case supplies its own key, deliberately left out of the set.
type world struct {
	rootPub  ed25519.PublicKey
	rootPriv ed25519.PrivateKey
	now      int64
	seq      int
	dv       *aat.Deriver
}

func newWorld(now int64) *world {
	pub, priv := keypair()
	w := &world{rootPub: pub, rootPriv: priv, now: now}
	// The Deriver's limits are the enforcement point's limits. A Deriver
	// looser than the verifier mints tokens that are denied on arrival, and
	// that denial would be a corpus bug reported as a warden false positive.
	w.dv = &aat.Deriver{Limits: evalLimits, Now: func() int64 { return now }}
	return w
}

// evalLimits are the §4.3/§4.4 bounds both the corpus and the wardend under
// test run with. wardend's defaults are -max-delegation-depth 8 and
// -max-token-lifetime 90d; MaxIATSkew is core.DefaultLimits'.
var evalLimits = core.Limits{
	MaxDelegationDepth: 8,
	MaxIATSkew:         core.DefaultLimits.MaxIATSkew,
	MaxTokenLifetime:   core.DefaultLimits.MaxTokenLifetime,
}

// Anchor is the trust anchor an enforcing wardend is configured with.
func (w *world) Anchor() *aat.JWK { return aat.NewJWK(w.rootPub) }

// jti issues a fresh lowercase UUIDv7-shaped identifier (§3.2 Table 1).
func (w *world) jti() string {
	w.seq++
	return fmt.Sprintf("01957a41-0081-7c20-bf3a-%012x", w.seq)
}

func keypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

// --- chains ----------------------------------------------------------------

// chain is a token sequence under construction, with the holder private key of
// each token so a PoP can be signed at any position.
//
// raws is the wire form and is authoritative: a forgery can be a string that
// aat.Parse refuses, in which case toks holds nil at that position. Presenting
// only what Parse accepts would restrict the corpus to the shapes our own
// parser likes, which is the opposite of the point.
type chain struct {
	w      *world
	raws   []string
	toks   []*aat.Token
	holder []ed25519.PrivateKey

	// err latches the first refusal from derive, so a scenario reads as a
	// straight sequence of narrowings. A benign scenario that latches an error
	// is never presented: warden's own §6 issuer refused to mint a delegation
	// this corpus holds legitimate, which is a finding about the corpus or
	// about CheckLink, not a false positive at the enforcement point.
	err error
}

func (c *chain) leaf() *aat.Token { return c.toks[len(c.toks)-1] }
func (c *chain) leafKey() ed25519.PrivateKey {
	return c.holder[len(c.holder)-1]
}
func (c *chain) depth() int { return len(c.raws) }

func (c *chain) push(raw string, tok *aat.Token, holder ed25519.PrivateKey) {
	c.raws = append(c.raws, raw)
	c.toks = append(c.toks, tok)
	c.holder = append(c.holder, holder)
}

// clone copies the chain so a forgery can branch off a shared prefix.
func (c *chain) clone() *chain {
	return &chain{
		w:      c.w,
		raws:   append([]string(nil), c.raws...),
		toks:   append([]*aat.Token(nil), c.toks...),
		holder: append([]ed25519.PrivateKey(nil), c.holder...),
	}
}

// truncate cuts the chain to its first n tokens: NOTES.md #6's prefix.
func (c *chain) truncate(n int) *chain {
	t := c.clone()
	t.raws, t.toks, t.holder = t.raws[:n], t.toks[:n], t.holder[:n]
	return t
}

// newChain mints a root. The root issuer key is also the root's holder key,
// which is what lets the issuer sign the first derivation (I1).
func newChain(w *world, tools string, maxDepth int) *chain {
	return newRoot(w, tools, maxDepth, nil)
}

func newRoot(w *world, tools string, maxDepth int, mut func(*aat.Claims)) *chain {
	cl := aat.Claims{
		JTI:                  w.jti(),
		Issuer:               RootIssuer,
		IssuedAt:             w.now - 60,
		Expires:              w.now + 3600,
		Confirmation:         aat.Confirmation{JWK: aat.NewJWK(w.rootPub)},
		DelegationDepth:      0,
		MaxDelegationDepth:   maxDepth,
		AuthorizationDetails: details(tools),
	}
	key := w.rootPriv
	if mut != nil {
		mut(&cl)
	}
	tok, err := aat.Mint(cl, key)
	if err != nil {
		panic(fmt.Sprintf("eval: mint root: %v", err))
	}
	c := &chain{w: w}
	c.push(tok.Compact(), tok, key)
	return c
}

// forgeRoot builds a root past aat.Mint, for the root shapes Mint refuses to
// produce. opt.signer defaults to the world's root issuer key, so the forgery
// is anchored unless a case deliberately supplies a foreign one.
func forgeRoot(w *world, tools string, maxDepth int, mut func(map[string]any), opt forgeOpts) *chain {
	pub, priv := opt.holderPub, opt.holderPriv
	if pub == nil {
		pub, priv = w.rootPub, w.rootPriv
	}
	m := map[string]any{
		"jti":                   w.jti(),
		"iss":                   RootIssuer,
		"iat":                   w.now - 60,
		"exp":                   w.now + 3600,
		"cnf":                   map[string]any{"jwk": aat.NewJWK(pub)},
		"del_depth":             0,
		"del_max_depth":         maxDepth,
		"authorization_details": details(tools),
	}
	if mut != nil {
		mut(m)
	}
	signer := opt.signer
	if signer == nil {
		signer = w.rootPriv
	}
	raw := signRaw(opt.alg, mustMarshal(m), signer, aat.NewJWK(w.rootPub))
	tok, _ := aat.Parse(raw)
	c := &chain{w: w}
	c.push(raw, tok, priv)
	return c
}

// reparent replaces the chain's root with another chain's root and leaves the
// derived tokens untouched. Each of them was minted under a different parent,
// so par_hash still points at the token it was actually derived from: §7 step
// 4q is the only thing standing between this chain and a permit.
func (c *chain) reparent(other *chain) *chain {
	r := c.clone()
	r.raws[0], r.toks[0], r.holder[0] = other.raws[0], other.toks[0], other.holder[0]
	return r
}

// repeatLeaf presents the leaf twice: §7 step 2c, cycle detection.
func (c *chain) repeatLeaf() *chain {
	r := c.clone()
	r.push(r.raws[len(r.raws)-1], r.toks[len(r.toks)-1], r.leafKey())
	return r
}

// derive extends the chain through draft §6, using aat.Deriver — warden's own
// issuing path, which refuses through the same core.CheckLink that §7 step 4
// runs at the enforcement point.
//
// This is the ONLY way a benign chain is ever extended. See eval/METHOD.md.
func (c *chain) derive(tools string, mut func(*aat.Derivation)) *chain {
	if c.err != nil {
		return c
	}
	pub, priv := keypair()
	parent := c.leaf()
	d := aat.Derivation{
		JTI:                c.w.jti(),
		IssuedAt:           parent.Claims.IssuedAt,
		Expires:            parent.Claims.Expires,
		HolderKey:          aat.NewJWK(pub),
		MaxDelegationDepth: parent.Claims.MaxDelegationDepth,
		Tools:              toolsMap(tools),
	}
	if mut != nil {
		mut(&d)
	}
	child, err := c.w.dv.Derive(parent, c.leafKey(), d)
	if err != nil {
		c.err = err
		return c
	}
	c.push(child.Compact(), child, priv)
	return c
}

// must is for an adversarial case's legitimate base chain, where a refusal is
// a bug in this file rather than a finding about warden.
func (c *chain) must() *chain {
	if c.err != nil {
		panic(fmt.Sprintf("eval: base chain: %v", c.err))
	}
	return c
}

// --- forging ---------------------------------------------------------------
//
// Everything below bypasses aat.Deriver and aat.Mint. An attacker does not
// call our issuing API, so neither does the adversarial corpus: forge builds
// the claim set a legitimate child would have carried, hands it to a mutator
// as a plain JSON object, and signs whatever comes back. Nothing between the
// mutation and the wire enforces an invariant.

type forgeOpts struct {
	// alg is the protected header alg. "" and "EdDSA" sign normally; "none"
	// emits the empty signature; "HS256" MACs the signing input under the
	// verifying key's raw public bytes, which is the confusion attack.
	alg string
	// signer overrides the signing key. Default is the parent's holder key —
	// the key a legitimate derivation would have used.
	signer ed25519.PrivateKey
	// holderPub/holderPriv override the child's own holder keypair, so a
	// forgery can hand the child's key to a party that should not hold it.
	holderPub  ed25519.PublicKey
	holderPriv ed25519.PrivateKey
}

// forge appends a forged child to the chain and returns the chain.
func (c *chain) forge(mut func(m map[string]any), opt forgeOpts) *chain {
	parent := c.leaf()
	pub, priv := opt.holderPub, opt.holderPriv
	if pub == nil {
		pub, priv = keypair()
	}
	iss, err := parent.Claims.Confirmation.JWK.ThumbprintURI()
	if err != nil {
		panic(err)
	}
	m := map[string]any{
		"jti":                   c.w.jti(),
		"iss":                   iss,
		"iat":                   parent.Claims.IssuedAt,
		"exp":                   parent.Claims.Expires,
		"cnf":                   map[string]any{"jwk": aat.NewJWK(pub)},
		"del_depth":             parent.Claims.DelegationDepth + 1,
		"del_max_depth":         parent.Claims.MaxDelegationDepth,
		"par_hash":              aat.ParentHash(parent),
		"authorization_details": parent.Claims.AuthorizationDetails,
	}
	if mut != nil {
		mut(m)
	}
	signer := opt.signer
	if signer == nil {
		signer = c.leafKey()
	}
	raw := signRaw(opt.alg, mustMarshal(m), signer, parent.Claims.Confirmation.JWK)
	// Parse refuses shapes an attacker can still put on the wire. When it
	// does, the token is carried as raw bytes with no *aat.Token behind it.
	tok, _ := aat.Parse(raw)
	c.push(raw, tok, priv)
	return c
}

// signRaw builds a compact JWS with no validation at all.
func signRaw(alg string, payload []byte, key ed25519.PrivateKey, verifyKey *aat.JWK) string {
	if alg == "" {
		alg = "EdDSA"
	}
	hdr := mustMarshal(map[string]any{"alg": alg, "typ": "JWT"})
	input := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	switch alg {
	case "none":
		return input + "."
	case "HS256":
		// §8.13: MAC the signing input under the public key the verifier would
		// have used to check an EdDSA signature. A verifier that selects its
		// algorithm from the header accepts this; one that selects from the
		// key type does not.
		pub, err := verifyKey.PublicKey()
		if err != nil {
			panic(err)
		}
		mac := hmac.New(sha256.New, pub)
		mac.Write([]byte(input))
		return input + "." + b64.EncodeToString(mac.Sum(nil))
	default:
		return input + "." + b64.EncodeToString(ed25519.Sign(key, []byte(input)))
	}
}

// --- presentation ----------------------------------------------------------

// popAt signs a PoP with the holder key at chain position i, over the leaf
// token identifier at that position.
func (c *chain) popAt(i int, tool string, args json.RawMessage, mut func(*aat.PoPClaims)) string {
	pc := aat.PoPClaims{
		JTI:      c.w.jti(),
		IssuedAt: c.w.now,
		Tool:     tool,
		Args:     argMap(args),
	}
	if c.toks[i] != nil {
		pc.TokenID = c.toks[i].Claims.JTI
	} else {
		// The token at i was refused by aat.Parse, so it has no readable jti.
		// A syntactically valid identifier keeps the failure where the case
		// puts it — in the chain — instead of in PoP encoding.
		pc.TokenID = c.w.jti()
	}
	if mut != nil {
		mut(&pc)
	}
	jwt, err := aat.SignPoP(pc, c.holder[i])
	if err != nil {
		panic(fmt.Sprintf("eval: sign pop: %v", err))
	}
	return jwt
}

func (c *chain) pop(tool string, args json.RawMessage) string {
	return c.popAt(len(c.holder)-1, tool, args, nil)
}

// meta builds the _meta member of §3.1's transport binding. Any of the three
// keys can be dropped by passing "" for it.
func meta(chainJSON, popJWT, spec string) json.RawMessage {
	m := map[string]json.RawMessage{}
	if chainJSON != "" {
		m[proxy.MetaChain] = json.RawMessage(chainJSON)
	}
	if popJWT != "" {
		m[proxy.MetaPoP] = mustMarshal(popJWT)
	}
	if spec != "" {
		m[proxy.MetaSpec] = mustMarshal(spec)
	}
	return mustMarshal(m)
}

// bind is the ordinary presentation: the whole chain, a PoP from the leaf
// holder, and the exact spec version.
func (c *chain) bind(tool string, args json.RawMessage) json.RawMessage {
	return meta(string(mustMarshal(c.raws)), c.pop(tool, args), proxy.SpecVersion)
}

// --- literals --------------------------------------------------------------

func details(tools string) []json.RawMessage {
	return []json.RawMessage{
		json.RawMessage(`{"type":"attenuating_agent_token","tools":` + tools + `}`),
	}
}

func toolsMap(tools string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(tools), &m); err != nil {
		panic(fmt.Sprintf("eval: tools literal %q: %v", tools, err))
	}
	return m
}

// argMap decodes arguments for a PoP hta member with UseNumber, so a literal
// like 9007199254740993 reaches the PoP payload as written rather than as the
// float64 that would collapse it. NOTES #7 is only reproducible this way.
func argMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		panic(fmt.Sprintf("eval: args %s: %v", raw, err))
	}
	return m
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
