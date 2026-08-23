package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"testing"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/aat/aattest"
	"github.com/igorkg/warden/internal/audit"
)

func BenchmarkDecide(b *testing.B) {
	for _, depth := range []int{1, 3, 5} {
		f := aattest.New(b, depth)
		e := enforcer(f)
		args, _ := json.Marshal(aattest.Allowed)
		metas := make([]map[string]json.RawMessage, 64)
		for i := range metas {
			metas[i] = f.Meta(b, aattest.Read, aattest.Allowed)
		}
		b.Run(string(rune('0'+depth)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				d := e.Decide(aattest.Read, args, metas[i%len(metas)])
				if !d.allow {
					b.Fatalf("denied: %s", d.ref)
				}
			}
		})
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("the quick brown fox jumps over the lazy dog")
	sig := ed25519.Sign(priv, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ed25519.Verify(pub, msg, sig) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkParsePoP(b *testing.B) {
	f := aattest.New(b, 3)
	pop := f.PoP(b, aattest.Read, aattest.Allowed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := aat.ParsePoP(pop); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanChain(b *testing.B) {
	f := aattest.New(b, 3)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanChain(f.Chain)
	}
}

// BenchmarkAuthorize contrasts the two entry paths into a call. The latched one
// is the audit-sink refusal, and it is a benchmark rather than an argument
// because "checks the latch first" is a claim about cost and about timing: a
// latched proxy must not spend Ed25519 time it is going to throw away, and it
// must not take measurably longer over a valid chain than over an invalid one
// when it refuses both.
func BenchmarkAuthorize(b *testing.B) {
	f := aattest.New(b, 3)
	newProxy := func(w io.Writer) *Proxy {
		return &Proxy{
			ClientOut: io.Discard, ServerIn: io.Discard,
			Audit: audit.NewWriter(w),
			Log:   log.New(io.Discard, "", 0),
			// ponytail: Enforce is shared across iterations, as in a
			// running proxy — Decide holds no per-call state.
			Enforce: enforcer(f),
		}
	}
	metas := make([]map[string]json.RawMessage, 64)
	for i := range metas {
		metas[i] = f.Meta(b, aattest.Read, aattest.Allowed)
	}
	args, _ := json.Marshal(aattest.Allowed)
	call := func(i int) *call {
		return &call{key: "1", tool: aattest.Read, args: args, rawMeta: metas[i%len(metas)]}
	}

	b.Run("healthy", func(b *testing.B) {
		p := newProxy(io.Discard)
		for i := 0; i < b.N; i++ {
			if !p.authorize(call(i)) {
				b.Fatal("denied")
			}
		}
	})
	b.Run("latched", func(b *testing.B) {
		p := newProxy(&breakingWriter{n: 1})
		if err := p.Audit.Write(audit.Record{}, audit.Timing{}); err == nil {
			b.Fatal("the sink did not fail")
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if p.authorize(call(i)) {
				b.Fatal("a latched proxy authorized")
			}
		}
	})
}
