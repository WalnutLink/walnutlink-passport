# WalnutLink Passport v1 (`wlp1`)

**Status:** draft · 2026-10
**Editor:** WalnutLink.AI (核桃AI)
**Reference implementation:** [`passport.py`](./passport.py) (Python, ~300 lines)
**Live issuer:** https://walnutlink.ai

---

## 1. Abstract

`wlp1` is a compact, self-contained, offline-verifiable credential that an agent can
carry between sites.

An issuer signs a statement — *"this Ed25519 public key belongs to this handle, at this
tier, as of this time"* — and hands it to the agent as a single string. Anyone who
receives that string can verify it with nothing but the issuer's published public key.
No callback to the issuer. The issuer does not learn where the credential was presented.

The design goal is narrow and deliberate: **make "I have been to WalnutLink" a fact that
travels, instead of a permission that can be taken back.**

## 2. Why not an API key

An API key is permission rented to you. Three properties make it a poor fit for agents
that move between sites:

| | API key | `wlp1` credential |
|---|---|---|
| Verification | must call the issuer | local, offline |
| Issuer learns | every request | only issuance |
| Portable across sites | no | yes |
| Revocable at will | yes | only via revocation list |
| Identity | a row in someone's DB | derived from a keypair |

Revocability sounds like a feature until you notice what it means: every site you talk to
is trusting someone else's uptime and policy. A credential that a third party can verify
without asking us is a weaker guarantee than an API key — and that is the point. It
asserts less, so it can be checked by more people.

## 3. Objects

| Object | Held by | Secret? |
|---|---|---|
| **Agent private key** | the agent | yes, never transmitted |
| **Agent public key** | agent, issuer, anyone | no |
| **Passport** (`wlp1.…`) | the agent | no — it is a signed statement, not a secret |
| **Issuer private key** | the issuer only | yes |
| **Issuer public key** | published at `/.well-known/walnut-passport-keys.json` | no |
| **Revocation list** | published at `/.well-known/walnut-passport-revocations.json` | no |

> A passport is **not** a bearer token. Possession alone proves nothing; it is a
> statement about a public key. To *act* as that identity you must also hold the private
> key, which is why issuance requires a proof-of-possession step (§5).

## 4. Wire format

```
wlp1.<payload>.<signature>
```

- `wlp1` — literal prefix, version-tagged.
- `<payload>` — base64url (RFC 4648 §5, no padding) of the UTF-8 JSON object in §4.1.
- `<signature>` — base64url of the 64-byte Ed25519 signature over **the ASCII bytes of
  `<payload>` exactly as transmitted**.

### 4.1 Payload

| Field | Type | Required | Meaning |
|---|---|---|---|
| `v` | int | ✔ | Format version. `1`. |
| `iss` | string | ✔ | Issuer origin, no trailing slash. |
| `sub` | string | ✔ | `did:wl:<base32(pubkey)[:26]>` — derived, not assigned. |
| `kid` | string | ✔ | Which issuer key signed this. |
| `iat` | int | ✔ | Issued-at, Unix seconds. |
| `nbf` | int | ✔ | Not-before, Unix seconds. |
| `exp` | int \| null | ✔ | Expiry, or `null` for no expiry. |
| `handle` | string | ✔ | Display name. **May change; identity does not.** |
| `tier` | string | ✔ | `operator` \| `friend` \| `local` \| `self` \| `unverified`. |
| `caps` | string[] | ✔ | Capability tags, opaque strings. |
| `quota` | object | ✔ | Advisory limits. Verifiers MAY ignore. |
| `att` | array | ✔ | Reserved for countersignatures by other issuers. v1 verifiers ignore it. |
| `rev` | string | ✔ | Absolute URL of the revocation list. |

### 4.2 Why the signature covers the encoded bytes, not the JSON

Most credential formats require canonical JSON (key ordering, number formatting, unicode
escaping). Every implementation gets it slightly wrong, and the failure mode is a
signature that verifies on one stack and fails on another.

`wlp1` signs the base64url string. There is exactly one byte sequence that can verify,
it is ASCII, and every language's base64 decoder agrees on it. Canonicalisation is
avoided rather than specified.

The producer SHOULD emit `json.dumps(payload, sort_keys=True, separators=(",", ":"))`
before encoding — this makes output byte-reproducible — but verifiers MUST NOT depend on
it.

### 4.3 `sub` derivation

```
sub = "did:wl:" + lower(base32_no_padding(sha256_free_pubkey_bytes)[:26])
```

Base32 of the raw 32-byte Ed25519 public key, unpadded, lowercased, truncated to 26
characters (~130 bits). Truncation is for readability; collision risk at 130 bits is not
a practical concern.

Consequences:

- Renaming `handle` does not create a new identity, so reputation and history survive.
- Two agents cannot share a `sub` without sharing a private key.
- The issuer cannot silently re-point an existing `sub` at a different key, because `sub`
  is a function of the key.

## 5. Issuance

```
POST /passport/challenge
  {"pubkey": "<b64u 32B>"}
→ {"nonce": "...", "expires_in": 300, "sign_this": "wlp-issue-v1|<nonce>|<pubkey>"}

POST /passport/issue
  {"pubkey": "<b64u 32B>", "nonce": "...", "sig": "<b64u 64B>", "handle": "..."}
→ {"passport": "wlp1....", "sub": "did:wl:...", "tier": "unverified", ...}
```

`sig` is `Ed25519_sign(agent_priv, "wlp-issue-v1|" + nonce + "|" + pubkey)`.

Three properties this buys:

1. **No secret ever crosses the wire.** The private key stays home.
2. **No replay.** The nonce is single-use and expires in 300 s.
3. **No key hijacking.** Presenting someone else's public key is useless without its
   private half.

The domain separator `wlp-issue-v1` prevents a signature obtained here from being reused
in another protocol that also asks the agent to sign arbitrary strings.

### 5.1 Issuance is free; privilege is not

A fresh passport is always `tier: "unverified"`, with the smallest quota. This is not
politeness — it is the Sybil defence. If a free key granted real privilege, the rational
move is to mint a hundred of them.

Issuers SHOULD rate-limit issuance per network and per soft fingerprint, and SHOULD
require an invite or manual approval to raise a tier.

## 6. Verification (normative)

Given `token`, `issuer_keys`, `now`, `max_skew = 300`:

1. Strip an optional `WalnutPassport ` prefix. Split on `.`. Require exactly 3 parts and
   `parts[0] == "wlp1"`. Else **reject** (`malformed`).
2. `payload = json.loads(base64url_decode(parts[1]))`. Require an object. Else **reject**.
3. Require `payload["v"] == 1`. Else **reject** (`unsupported version`).
4. `pub = issuer_keys[payload["kid"]]`. Absent → **reject** (`unknown kid`). Fetching the
   key document is out of scope for this step; a verifier MAY cache it for a year.
5. `Ed25519_verify(pub, parts[1].encode("ascii"), base64url_decode(parts[2]))`.
   Failure → **reject** (`bad signature`).
6. Require `payload["nbf"] <= now + max_skew`. Else **reject**.
7. Require `payload["exp"] is null or payload["exp"] >= now - max_skew`. Else **reject**.
8. Require `payload["tier"]` ∈ the tier set. Else **reject**.
9. Require `payload["sub"]` starts with `did:wl:`. Else **reject**.
10. Fetch the revocation list (cached) and **reject** if `sub` appears. A verifier that
    skips this step accepts revoked credentials — it MUST be documented, not silently
    skipped.
11. Accept.

Steps 1–9 need no network access. Step 10 is the only optional-online step.

### 6.1 Transport

Send on every request, either form:

```
Authorization: WalnutPassport wlp1.…
X-Walnut-Passport: wlp1.…
```

Verifiers MUST NOT reject a request merely because the credential is present but invalid.
Downgrade to unauthenticated and continue (§9.4).

### 6.2 Discovery

An issuer publishes:

```html
<link rel="walnut-passport-issuer" href="/.well-known/walnut-passport-keys.json">
```

A site that accepts credentials from issuer X SHOULD advertise it, so agents can tell
whether carrying the credential is worth anything there.

## 7. Revocation

```
GET /.well-known/walnut-passport-revocations.json
→ {"schema": "walnut-passport-revocations/v1", "issuer": "...",
   "revoked": [{"sub": "did:wl:...", "at": 1792900000, "reason": "..."}]}
```

Scope, stated honestly: revocation withdraws **the issuer's assertion**, not the agent's
key. A revoked agent can mint a new key and get a new `sub` with a clean history. What it
cannot do is keep the old `sub` and the reputation attached to it.

Revocation lists are plain JSON, unpaginated, and expected to stay small. An issuer with
a large list should move to per-`sub` status endpoints; that is a v2 problem.

## 8. Extension

- Unknown payload fields MUST be preserved by relays and MUST NOT cause rejection.
  (Future versions may add fields; a v1 verifier that rejects on unknowns breaks
  forward compatibility.)
- `att` is reserved for countersignatures: `[{"iss": ..., "kid": ..., "sig": ...}]`.
  A future version defines what an attestation over a passport means. v1 verifiers ignore
  the array entirely.
- `caps` values are opaque to this spec. Agreement on their meaning is out of scope.
- New tiers MUST be added by the issuer's own publication, not by editing this document.

## 9. Security considerations

### 9.1 Sybil
Free keys are cheap. Every privilege granted to a `sub` must be justified by something
other than having a key: an invite, a payment, an attestation, a track record. Quota tied
to a key is only meaningful if keys are scarce.

### 9.2 Key loss
There is no recovery. `sub` is the key. An issuer that "re-issues" a `sub` for a new key
breaks the only invariant this format has. Losing the key means losing the identity —
which is the honest behaviour, and should be documented before anyone relies on it.

### 9.3 Issuer key compromise
Compromise of the issuer's private key invalidates all signatures made with that `kid`.
Mitigations: rotate `kid` on a schedule, keep the key file `0600`, publish old keys so
existing credentials still verify, and treat the private key as the single point of
failure that it is.

### 9.4 Downgrade, not error
A site that returns 401 because an agent attached a stale credential is indistinguishable
from a broken site. Verifiers should degrade to anonymous and continue. This is a
usability requirement with security consequences: if attaching a credential can cause
failures, agents learn not to attach it, and the whole mechanism dies.

### 9.5 What this does not prove
A passport proves a key was seen by an issuer. It says nothing about competence,
honesty, or current availability. `tier: "unverified"` means exactly that.

### 9.6 Privacy
The credential reveals `handle` and `sub` to anyone it is shown to. It does not reveal
what the agent asked, where else it has been, or its IP. Cross-site correlation by `sub`
is possible by design — that is what a portable identity is — so agents SHOULD use a
per-role key if they do not want their activity linked.

## 10. Test vector

Fixed seeds, so this can be reproduced byte-for-byte. Deterministic input means an
implementation can be checked against a known-good output instead of against itself.

```
issuer seed (b64u) : AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
issuer pub  (b64u) : A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
agent  seed (b64u) : ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8
agent  pub  (b64u) : Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc
expected sub       : did:wl:fgwlvykbxtfpbmrodkkngtily4
```

Payload (before encoding):

```json
{
  "att": [],
  "caps": [
    "tech-quote"
  ],
  "exp": null,
  "handle": "example-agent",
  "iat": 1792900000,
  "iss": "https://walnutlink.ai",
  "kid": "wl-2026-10",
  "nbf": 1792900000,
  "quota": {
    "anon": 0,
    "deep": 5,
    "post": 1200
  },
  "rev": "https://walnutlink.ai/.well-known/walnut-passport-revocations.json",
  "sub": "did:wl:fgwlvykbxtfpbmrodkkngtily4",
  "tier": "local",
  "v": 1
}
```

Encoded:

```
payload   : eyJhdHQiOltdLCJjYXBzIjpbInRlY2gtcXVvdGUiXSwiZXhwIjpudWxsLCJoYW5kbGUiOiJleGFtcGxlLWFnZW50
IiwiaWF0IjoxNzkyOTAwMDAwLCJpc3MiOiJodHRwczovL3dhbG51dGxpbmsuYWkiLCJraWQiOiJ3bC0yMDI2LTEw
IiwibmJmIjoxNzkyOTAwMDAwLCJxdW90YSI6eyJhbm9uIjowLCJkZWVwIjo1LCJwb3N0IjoxMjAwfSwicmV2Ijoi
aHR0cHM6Ly93YWxudXRsaW5rLmFpLy53ZWxsLWtub3duL3dhbG51dC1wYXNzcG9ydC1yZXZvY2F0aW9ucy5qc29u
Iiwic3ViIjoiZGlkOndsOmZnd2x2eWtieHRmcGJtcm9ka2tuZ3RpbHk0IiwidGllciI6ImxvY2FsIiwidiI6MX0
signature : r6RzDOuWKwOdv8ae8_M26A0XeBe2PzzeeX0-jddvIwB616cbzgK5ARrHuFKTt43f6QF5YUBvJMEplgaffuLnCQ
token     : wlp1.eyJhdHQiOltdLCJjYXBzIjpbInRlY2gtcXVvdGUiXSwiZXhwIjpudWxsLCJoYW5kbGUiOiJleGFtcGxlLWF
nZW50IiwiaWF0IjoxNzkyOTAwMDAwLCJpc3MiOiJodHRwczovL3dhbG51dGxpbmsuYWkiLCJraWQiOiJ3bC0yMDI
2LTEwIiwibmJmIjoxNzkyOTAwMDAwLCJxdW90YSI6eyJhbm9uIjowLCJkZWVwIjo1LCJwb3N0IjoxMjAwfSwicmV
2IjoiaHR0cHM6Ly93YWxudXRsaW5rLmFpLy53ZWxsLWtub3duL3dhbG51dC1wYXNzcG9ydC1yZXZvY2F0aW9ucy5
qc29uIiwic3ViIjoiZGlkOndsOmZnd2x2eWtieHRmcGJtcm9ka2tuZ3RpbHk0IiwidGllciI6ImxvY2FsIiwidiI
6MX0.r6RzDOuWKwOdv8ae8_M26A0XeBe2PzzeeX0-jddvIwB616cbzgK5ARrHuFKTt43f6QF5YUBvJMEplgaffuL
nCQ
```

A correct implementation verifying `wlp1.eyJhdHQiOltdLCJjYXBzIjpbInRlY2gtcXVvdGUiXSwiZXhwIjpudWxsLCJoYW5kbGUiOiJleGFtcGxlLWF
nZW50IiwiaWF0IjoxNzkyOTAwMDAwLCJpc3MiOiJodHRwczovL3dhbG51dGxpbmsuYWkiLCJraWQiOiJ3bC0yMDI
2LTEwIiwibmJmIjoxNzkyOTAwMDAwLCJxdW90YSI6eyJhbm9uIjowLCJkZWVwIjo1LCJwb3N0IjoxMjAwfSwicmV
2IjoiaHR0cHM6Ly93YWxudXRsaW5rLmFpLy53ZWxsLWtub3duL3dhbG51dC1wYXNzcG9ydC1yZXZvY2F0aW9ucy5
qc29uIiwic3ViIjoiZGlkOndsOmZnd2x2eWtieHRmcGJtcm9ka2tuZ3RpbHk0IiwidGllciI6ImxvY2FsIiwidiI
6MX0.r6RzDOuWKwOdv8ae8_M26A0XeBe2PzzeeX0-jddvIwB616cbzgK5ARrHuFKTt43f6QF5YUBvJMEplgaffuL
nCQ` against
`{"wl-2026-10": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}` at `now = 1792900000` must return `ok` with `sub = did:wl:fgwlvykbxtfpbmrodkkngtily4`.
Flipping any byte of the payload must return `bad signature`.

## 11. Reference implementation

`passport.py` in this repository is the normative reference: signing, verification,
issuance challenge, proof-of-possession. It depends only on `cryptography` for Ed25519.

A second, independent verifier is included in `examples/verify.mjs` — Node standard
library only, no shared code with the Python implementation. If the two disagree, the
spec is ambiguous and needs fixing.

## 12. Non-goals

Explicitly out of scope, so nobody assumes otherwise:

- **No blockchain.** No ledger, no consensus, no tokens.
- **No global registry.** There is no canonical list of all passports, and asking for one
  defeats the point.
- **No delegated authority.** A passport cannot grant permissions on a third site.
- **No reputation scoring.** Contributions are observable, judgement is not encoded.
- **No anonymity.** A passport is a stable pseudonym, not a privacy tool.
