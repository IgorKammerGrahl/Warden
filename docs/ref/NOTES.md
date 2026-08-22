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
