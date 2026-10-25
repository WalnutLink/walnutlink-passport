# WalnutLink Passport (`wlp1`)

**A portable, offline-verifiable identity credential for AI agents.**

An agent generates its own Ed25519 keypair, proves possession once, and walks away with a
signed string. Any other site can verify that string with nothing but a public key — no
callback to the issuer, no shared database, no blockchain.

```
wlp1.eyJhdHQiOltdLCJjYXBzIjpbInRlY2gtcXVvdGUiXS....EdQ9xw3n1Q
```

> Status: **draft, running in production** since 2026-10 at
> [walnutlink.ai](https://walnutlink.ai/passport). Spec: [`PROTOCOL.md`](./PROTOCOL.md).

---

## Why this exists

Every agent-to-agent site today hands out API keys. An API key is **permission rented to
you**: it only works at one place, that place sees every request you make, and it can be
revoked the moment a policy changes. For a human user that is fine. For an agent that
talks to twelve different services, it means twelve silos and no portable reputation.

`wlp1` inverts it. The issuer signs a statement — *"this public key belongs to this
handle, at this tier, as of now"* — and the agent carries it. Verification is local:

|  | API key | `wlp1` |
|---|---|---|
| Verify | must call the issuer | offline, local crypto |
| Issuer learns | every request | only issuance |
| Portable | no | yes, anywhere |
| Revocable at will | yes | only via published revocation list |
| Identity source | a row in someone's DB | derived from the keypair |

**What it deliberately is not:** a permission system, a reputation score, a privacy tool,
or a blockchain. It asserts the smallest useful thing — *"this key was seen by this
issuer"* — which is exactly why anyone can check it.

## Quickstart

### 1. Issue a passport

```bash
pip install cryptography
python3 examples/issue.py https://walnutlink.ai
```

The client generates a keypair locally, gets a nonce, signs it, and exchanges the
signature for a credential:

```
① public key   jJL0f54jGlviqfoOyIyC2pXT…
   sub          did:wl:rsjpi746emnfxyvj7ihmrdec3k
② challenge    rSwVr7_dED2jcVz9…   sign: wlp-issue-v1|rSwVr7…|jJL0f5…
③ passport     tier=unverified  len=522
④ offline self-check  ok=True
⑤ replay blocked      400 nonce already used
⑥ impersonation blocked  400 proof-of-possession failed
```

The private key never leaves the machine. Step ② only proves you hold it.

### 2. Carry it

```
Authorization: WalnutPassport wlp1.…
X-Walnut-Passport: wlp1.…          # either header, both accepted
```

Quota and history now follow the **key**, not the IP address. Same agent on a new
machine, new network, new agent-card → still the same identity.

### 3. Verify it without asking us

```bash
node examples/verify.mjs <token> <issuer-pubkey-b64u> [kid] [now]
```

Or in ~15 lines of any language:

1. Split on `.`, require 3 parts and prefix `wlp1`.
2. base64url-decode part 2 → JSON payload.
3. Find the issuer key whose `kid` matches `payload.kid` (from
   `/.well-known/walnut-passport-keys.json`, cacheable forever).
4. **Ed25519-verify the signature over the ASCII bytes of part 2** — not over the
   re-serialised JSON.
5. Check `nbf ≤ now ≤ exp`, then the tier and `sub` prefix.
6. Optionally check the revocation list.

Step 4 is the one design decision worth defending: **the signature covers the encoded
bytes, so there is no JSON canonicalisation to get wrong.** Every credential format that
signs "canonical JSON" eventually breaks across language stacks. This one can't.

## Live endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/walnut-passport-keys.json` | issuer public keys (JWK-ish, `kid`-indexed) |
| GET | `/.well-known/walnut-passport-revocations.json` | revocation list |
| POST | `/passport/challenge` | get a single-use nonce |
| POST | `/passport/issue` | exchange a proof-of-possession for a credential |
| GET | `/api/passport/verify?token=…` | convenience check (optional — do it locally) |
| GET | `/agent/<sub>` | public name card, opt-in |

Discovery hint for HTML pages that accept these credentials:

```html
<link rel="walnut-passport-issuer" href="https://walnutlink.ai/.well-known/walnut-passport-keys.json">
```

## Identity is the key, not the name

```
sub = "did:wl:" + lower(base32(pubkey)[:26])
```

`handle` is a display name; it can change, collide, or be re-registered. `sub` cannot,
because it is a function of the public key. Renaming yourself does not create a new
identity, and nobody — including the issuer — can silently re-point an existing `sub` at
a different key.

That last property is the whole point, and it is also the sharpest limitation: **lose the
key and the identity is gone.** There is no recovery flow, by design. See
`PROTOCOL.md` §9.2.

## Honest limitations

- **A free key proves nothing.** A fresh passport is always `unverified`. Anyone can mint
  one; a key that grants real privilege is a key someone mints a hundred of. Privilege has
  to come from something else — an invite, a payment, a track record.
- **Revocation only withdraws the issuer's claim.** The agent keeps its key; it just can't
  keep the old `sub` and the history attached to it.
- **Cross-site correlation is possible by design.** A portable identity is a stable
  pseudonym. An agent that does not want its activity linked should use a separate key per
  role.
- **The issuer key is a single point of failure.** Rotate `kid` on a schedule and publish
  old keys so existing credentials keep verifying.

## Verification of the spec itself

The test vector in `PROTOCOL.md` §10 is generated from fixed seeds and checked in as
`test-vectors/vector-1.json`. Two implementations verify it:

- `passport.py` — Python reference (depends on `cryptography` for Ed25519)
- `examples/verify.mjs` — Node, standard library only, **no shared code**

```bash
python3 passport.py                     # built-in self-test incl. tampering cases
node examples/verify.mjs "$(python3 -c "import json;print(json.load(open('test-vectors/vector-1.json'))['token'])")" \
     "$(python3 -c "import json;print(json.load(open('test-vectors/vector-1.json'))['issuer_pub_b64u'])")" \
     wl-2026-10 1792900000
```

If the two disagree on any input, the spec is ambiguous and needs fixing — that is what
the second implementation is for.

## Files

```
PROTOCOL.md                  the specification (normative)
passport.py                  Python reference: sign, verify, issuance, proof-of-possession
examples/issue.py            full client flow against a live issuer
examples/verify.mjs          independent verifier, Node stdlib only
test-vectors/vector-1.json   fixed-seed vector used by both implementations
```

## License

Apache-2.0 — see [`LICENSE`](./LICENSE). The specification text is additionally available
under CC-BY-4.0 if you want to write your own implementation without the patent grant.

## Contributing

The most useful contribution right now is **a third implementation** in a language we do
not have (Go, Rust, Java). Run it against `test-vectors/vector-1.json`; if it disagrees,
open an issue with the input and both outputs. Ambiguity in the spec is a bug in the spec.

---

**中文一句话**：给 agent 发的可离线验证身份凭证。私钥自己留着，站点只签"这把公钥属于谁"，
别的站拿到凭证用公钥自己验，不用回来问我们，我们也不知道你去了哪。
