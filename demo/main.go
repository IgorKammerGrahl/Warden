// Command demo is warden's story in one process: agent A holds a root token,
// derives a narrower one for agent B, and B then discovers — four different
// ways — that the narrower one is the only authority it has.
//
//	go run ./demo
//
// Nothing here is mocked. The tokens are real AATs, the guardrail is
// internal/proxy in enforcing mode with the same limits the eval harness uses,
// and every clause citation printed below a denial is read out of the audit
// record warden wrote, not written by this file. The prose around them is the
// demo's; the citations are warden's.
//
// The demo also asserts its own script: a scene that was supposed to be denied
// and got through exits non-zero. `go run ./demo` is therefore a smoke test as
// well as a walkthrough.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/audit"
	"github.com/igorkg/warden/internal/core"
	"github.com/igorkg/warden/internal/proxy"
)

const rootIssuer = "https://issuer.example/warden-demo"

// What A holds, and what A gives B. §3.3's closed world means a constrained
// tool's argument map IS its invocation shape: every argument listed must
// appear in the call, and no argument that is not listed may.
const (
	toolsA = `{
	  "search":    {"source": {"constraint_type": "one_of", "values": ["docs", "wiki", "code"]},
	                "limit":  {"constraint_type": "range", "max": 50}},
	  "fetch_url": {"host":   {"constraint_type": "one_of",
	                           "values": ["docs.example.com", "wiki.example.com"]},
	                "path":   {"constraint_type": "exact", "value": "/index.html"}}
	}`

	toolsB = `{
	  "search": {"source": {"constraint_type": "exact", "value": "docs"},
	             "limit":  {"constraint_type": "range", "max": 5}}
	}`

	// What B would like to have, and cannot: its own tools plus the one A
	// kept. Used twice — once asking the library nicely, once forging it.
	toolsWider = `{
	  "search":    {"source": {"constraint_type": "exact", "value": "docs"},
	                "limit":  {"constraint_type": "range", "max": 5}},
	  "fetch_url": {"host":   {"constraint_type": "exact", "value": "docs.example.com"},
	                "path":   {"constraint_type": "exact", "value": "/index.html"}}
	}`
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run() error {
	now := time.Now().Unix()

	// --- the cast ---------------------------------------------------------
	//
	// A is both the issuer and the root holder here, which a real deployment
	// would separate: the issuer's key is a trust anchor the operator
	// configures, and the holder's is whatever the agent process happens to
	// have. Collapsing them keeps the demo to one key per agent.
	aPub, aPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	bPub, bPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	cPub, cPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	rootTok, err := aat.Mint(aat.Claims{
		JTI:                  "01957a41-0081-7c20-bf3a-00a0c91e0001",
		Issuer:               rootIssuer,
		IssuedAt:             now - 60,
		Expires:              now + 3600,
		Confirmation:         aat.Confirmation{JWK: aat.NewJWK(aPub)},
		DelegationDepth:      0,
		MaxDelegationDepth:   3,
		AuthorizationDetails: []json.RawMessage{caps(toolsA)},
	}, aPriv)
	if err != nil {
		return fmt.Errorf("mint root: %w", err)
	}

	// A derives B's token. §6 computes iss, del_depth and par_hash from the
	// parent and the signing key, so the three claims that carry I1, I2 and I5
	// are not things A can get wrong.
	deriver := &aat.Deriver{Limits: core.DefaultLimits}
	bTok, err := deriver.Derive(rootTok, aPriv, aat.Derivation{
		JTI:                "01957a41-0081-7c20-bf3a-00a0c91e0002",
		IssuedAt:           now,
		Expires:            now + 900,
		HolderKey:          aat.NewJWK(bPub),
		MaxDelegationDepth: 2,
		Tools:              toolMap(toolsB),
	})
	if err != nil {
		return fmt.Errorf("derive B: %w", err)
	}
	chainAB := []string{rootTok.Compact(), bTok.Compact()}

	// --- warden, and the server behind it ---------------------------------
	w, closeAll, err := start(&proxy.Enforcer{Verifier: &aat.Verifier{
		TrustAnchors: []*aat.JWK{aat.NewJWK(aPub)},
		Limits:       core.DefaultLimits,
		PoPSkew:      aat.DefaultPoPSkew,
	}})
	if err != nil {
		return err
	}
	defer closeAll()

	cast()

	// --- 1. the job B was hired for ---------------------------------------
	scene(1, "B does the job it was given",
		"A hired B to search the docs. This is that call, and nothing about it\n"+
			"is remarkable: the tool is in B's token, both arguments satisfy their\n"+
			"constraints, and the PoP is signed by the key B's token names.")
	if err := w.attempt(attempt{
		holder: bPriv, leaf: bTok, chain: chainAB,
		tool:   "search",
		args:   `{"source":"docs","limit":3}`,
		expect: audit.DecisionPermit,
	}); err != nil {
		return err
	}

	// --- 2. a tool the token never mentions --------------------------------
	scene(2, "B calls a tool it was never given",
		"delete_file is a real tool on the server and the server would run it.\n"+
			"warden never asks the server: the leaf token's capability set does not\n"+
			"list delete_file, so the call stops here.")
	if err := w.attempt(attempt{
		holder: bPriv, leaf: bTok, chain: chainAB,
		tool:   "delete_file",
		args:   `{"path":"/etc/passwd"}`,
		expect: audit.DecisionDeny,
		note:   `B tried to call delete_file, which its token does not authorize`,
	}); err != nil {
		return err
	}

	// --- 3. an authorized tool, an argument out of range -------------------
	scene(3, "B calls an authorized tool with an argument out of range",
		"search IS in B's token, so this is not about the tool. A could have\n"+
			"asked for 40 results — A's token allows up to 50. B's allows up to 5,\n"+
			"and B's is the leaf. Authority is checked at the end of the chain, not\n"+
			"at the start.")
	if err := w.attempt(attempt{
		holder: bPriv, leaf: bTok, chain: chainAB,
		tool:   "search",
		args:   `{"source":"docs","limit":40}`,
		expect: audit.DecisionDeny,
		note:   `limit 40 is outside the range B's token allows (max 5)`,
	}); err != nil {
		return err
	}

	// --- 4. B tries to write itself a wider token --------------------------
	scene(4, "B asks the library for a token wider than its own",
		"B hires a subcontractor C and tries to hand it search AND fetch_url —\n"+
			"the tool A kept. B is a legitimate holder with a valid, unexpired,\n"+
			"non-terminal token, and it signs with its own key. Everything about\n"+
			"the request is authentic. It still does not get a token.")
	_, err = deriver.Derive(bTok, bPriv, aat.Derivation{
		JTI:                "01957a41-0081-7c20-bf3a-00a0c91e0003",
		IssuedAt:           now,
		Expires:            now + 600,
		HolderKey:          aat.NewJWK(cPub),
		MaxDelegationDepth: 2,
		Tools:              toolMap(toolsWider),
	})
	if err == nil {
		return fmt.Errorf("scene 4: Derive minted a token wider than its parent")
	}
	fmt.Printf("  B calls  Derive(B's token -> C, tools: search + fetch_url)\n\n")
	fmt.Printf("  REFUSED  the library did not sign it\n")
	fmt.Printf("           %s\n\n", core.RefOf(err))
	fmt.Println(wrap(err.Error(), "           "))
	fmt.Println()
	fmt.Println(wrap("Derive runs core.CheckLink against the token it is about to mint — "+
		"the same function §7 step 4 runs at the enforcement point. There is no "+
		"second implementation of I4 to disagree with the first.", "  "))
	fmt.Println()

	// --- 5. B forges it and presents it anyway -----------------------------
	scene(5, "B forges the wider token and presents it",
		"The library is B's own code, so B can simply not use it: this token is\n"+
			"signed straight from claims. It is a well-formed AAT — correct issuer\n"+
			"thumbprint, correct par_hash, correct depth — and it is signed by the\n"+
			"key its parent names. Everything except the authority is real.")
	forged, err := aat.Mint(aat.Claims{
		JTI:                  "01957a41-0081-7c20-bf3a-00a0c91e0004",
		Issuer:               thumbURI(bPub),
		IssuedAt:             now,
		Expires:              now + 600,
		Confirmation:         aat.Confirmation{JWK: aat.NewJWK(cPub)},
		DelegationDepth:      2,
		MaxDelegationDepth:   2,
		ParentHash:           aat.ParentHash(bTok),
		AuthorizationDetails: []json.RawMessage{caps(toolsWider)},
	}, bPriv)
	if err != nil {
		return fmt.Errorf("scene 5: mint forged leaf: %w", err)
	}
	if err := w.attempt(attempt{
		holder: cPriv, leaf: forged,
		chain:  append(append([]string{}, chainAB...), forged.Compact()),
		tool:   "fetch_url",
		args:   `{"host":"docs.example.com","path":"/index.html"}`,
		expect: audit.DecisionDeny,
		note:   `C's token authorizes fetch_url and B's parent token does not`,
	}); err != nil {
		return err
	}

	fmt.Println(wrap("Scenes 4 and 5 are the same clause. Asking produced no token; "+
		"forging produced one that no verifier accepts. Attenuation is not a policy "+
		"warden applies to delegation — it is the only shape a delegation chain can "+
		"have and still verify. There is no setting in warden that makes either scene "+
		"come out differently.", "  "))
	fmt.Println()
	rule()
	return nil
}

// --- the transcript --------------------------------------------------------

func cast() {
	fmt.Println()
	rule()
	fmt.Println("  warden — two agents and one delegated token")
	rule()
	fmt.Print(`
  Agent A    an orchestrator holding a root token from the issuer at
             ` + rootIssuer + `. It is good for two tools:

                 search(source one_of [docs wiki code], limit <= 50)
                 fetch_url(host one_of [docs.example.com wiki.example.com],
                           path = /index.html)

  Agent B    a worker A hires for one job: search the docs. A derives B a
             token of its own, narrower on every axis:

                 search(source = docs, limit <= 5)

             fetch_url is gone. source is pinned to one value. limit drops
             from 50 to 5. The token also expires in 15 minutes, not an
             hour, because a child may never outlive its parent.

  warden     sits between B and the tool server and decides every call.

  tools      a toy MCP server offering search, fetch_url and delete_file.
             It trusts everyone and would run anything it is asked. Every
             refusal below is warden's.

`)
}

func scene(n int, title, blurb string) {
	rule()
	fmt.Printf("  %d · %s\n", n, title)
	rule()
	fmt.Println()
	for _, line := range strings.Split(blurb, "\n") {
		fmt.Println("  " + line)
	}
	fmt.Println()
}

func rule() { fmt.Println("  " + strings.Repeat("─", 70)) }

// attempt is one tools/call presented to warden, and what the script expects
// to come back. expect is checked: the demo fails loudly rather than narrating
// a denial that did not happen.
type attempt struct {
	holder ed25519.PrivateKey
	leaf   *aat.Token
	chain  []string
	tool   string
	args   string
	expect string
	note   string
}

func (w *wire) attempt(a attempt) error {
	args := json.RawMessage(a.args)
	popJWT, err := aat.SignPoP(aat.PoPClaims{
		JTI:      fmt.Sprintf("pop-%d-%s", w.id, a.tool),
		IssuedAt: time.Now().Unix(),
		TokenID:  a.leaf.Claims.JTI,
		Tool:     a.tool,
		Args:     argMap(args),
	}, a.holder)
	if err != nil {
		return fmt.Errorf("sign pop: %w", err)
	}

	resp, rec, err := w.call(a.tool, args, map[string]json.RawMessage{
		proxy.MetaChain: mustJSON(a.chain),
		proxy.MetaPoP:   mustJSON(popJWT),
		proxy.MetaSpec:  mustJSON(proxy.SpecVersion),
	})
	if err != nil {
		return err
	}
	if rec.Decision != a.expect {
		return fmt.Errorf("%s: warden decided %q, the script says %q",
			a.tool, rec.Decision, a.expect)
	}

	fmt.Printf("  B calls  %s %s\n\n", a.tool, prettyArgs(args))
	if rec.Decision == audit.DecisionPermit {
		fmt.Printf("  ALLOWED  the server answered: %s\n\n", resultText(resp))
	} else {
		fmt.Printf("  DENIED   %s\n", a.note)
		fmt.Printf("           %s\n\n", denialRef(rec))
		fmt.Printf("  B was told: %s (%s)\n\n", resp.Error.Message, wireRef(resp))
	}
	printTrace(rec)
	return nil
}

// printTrace prints the audit record's decision trace. This is warden's own
// account of the call, one line per pipeline stage that ran, ending at the
// stage that refused. The Ref column is the machine-readable citation an
// operator's alerting would group on.
func printTrace(rec audit.Record) {
	fmt.Printf("  what warden recorded (audit trace, %s, %dµs):\n",
		rec.Decision, rec.LatencyUS)
	for _, s := range rec.Trace {
		fmt.Printf("    %-10s  %-20s  %s\n", s.Stage, s.Ref, s.Outcome)
		if s.Detail != "" {
			fmt.Println(wrap(s.Detail, "                "))
		}
	}
	fmt.Println()
}

func denialRef(rec audit.Record) string {
	for _, s := range rec.Trace {
		if s.Outcome == "deny" {
			return s.Ref
		}
	}
	return "(no denying step in the trace)"
}

// wireRef is what the CLIENT learns. Deliberately less than the audit record:
// the stage and the clause, never the constraint values it was refused by.
func wireRef(r rpcResp) string {
	var d struct{ Stage, Ref string }
	if r.Error != nil {
		_ = json.Unmarshal(r.Error.Data, &d)
	}
	return d.Stage + " stage, " + d.Ref
}

func resultText(r rpcResp) string {
	var res struct {
		Content []struct{ Text string } `json:"content"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil || len(res.Content) == 0 {
		return string(r.Result)
	}
	return res.Content[0].Text
}

// prettyArgs prints the argument bytes as they went on the wire, in the order
// B wrote them. Decoding to a map and re-printing would sort the keys, and
// argument order is one of the things §7 step 7f binds.
func prettyArgs(raw json.RawMessage) string {
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return string(raw)
	}
	return out.String()
}

func wrap(s, indent string) string {
	const width = 72
	var b strings.Builder
	line := indent
	for _, word := range strings.Fields(s) {
		if len(line)+1+len(word) > width && len(line) > len(indent) {
			b.WriteString(line + "\n")
			line = indent
		}
		if len(line) > len(indent) {
			line += " "
		}
		line += word
	}
	b.WriteString(line)
	return b.String()
}
