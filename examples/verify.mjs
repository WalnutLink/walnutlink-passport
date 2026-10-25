// Independent verifier for WalnutLink Passport v1 (wlp1).
// Node standard library only — no shared code with the Python reference
// implementation. If the two disagree, the spec is ambiguous and needs fixing.
//
//   node verify.mjs wlp1.eyJ... <issuer-public-key-b64u> [kid] [now]
//
// Exits 0 and prints the payload on success, exits 1 on any failure.

import crypto from 'node:crypto'

const [, , tokenArg, pubArg, kidArg, nowArg] = process.argv
if (!tokenArg || !pubArg) {
  console.error('usage: node verify.mjs <token> <issuer-pubkey-b64u> [kid] [now]')
  process.exit(2)
}

function b64uDec(s) {
  const p = s.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(p.padEnd(Math.ceil(p.length / 4) * 4, '='), 'base64')
}

function verifyToken(token, issuerKeys, now = Math.floor(Date.now() / 1000), maxSkew = 300) {
  const t = token.trim().replace(/^WalnutPassport\s+/i, '')
  const parts = t.split('.')
  if (parts.length !== 3 || parts[0] !== 'wlp1') return [false, null, 'malformed']

  const [, body, sigB64] = parts
  let payload
  try { payload = JSON.parse(b64uDec(body).toString('utf8')) }
  catch { return [false, null, 'payload is not base64url JSON'] }
  if (typeof payload !== 'object' || payload === null) return [false, null, 'bad payload']

  if (payload.v !== 1) return [false, payload, 'unsupported version']

  const pub = issuerKeys[payload.kid]
  if (!pub) return [false, payload, 'unknown kid: ' + payload.kid]

  // Ed25519 SubjectPublicKeyInfo header, then the 32 raw bytes.
  const der = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), pub,
  ])
  let ok = false
  try {
    ok = crypto.verify(null,
      Buffer.from(body, 'ascii'),                       // the encoded bytes, not the JSON
      crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }),
      b64uDec(sigB64))
  } catch { return [false, payload, 'signature check threw'] }
  if (!ok) return [false, payload, 'bad signature']

  if ((payload.nbf || 0) > now + maxSkew) return [false, payload, 'not yet valid']
  if (payload.exp !== null && payload.exp !== undefined && payload.exp < now - maxSkew)
    return [false, payload, 'expired']
  if (!['operator', 'friend', 'local', 'self', 'unverified'].includes(payload.tier))
    return [false, payload, 'unknown tier']
  if (!String(payload.sub || '').startsWith('did:wl:'))
    return [false, payload, 'bad sub']

  return [true, payload, 'ok']
}

const keys = { [kidArg || 'wl-2026-10']: b64uDec(pubArg) }
const now = nowArg ? parseInt(nowArg, 10) : Math.floor(Date.now() / 1000)
const [ok, payload, why] = verifyToken(tokenArg, keys, now)

if (ok) {
  console.log('VALID')
  console.log(JSON.stringify(payload, null, 2))
  process.exit(0)
} else {
  console.log('INVALID: ' + why)
  process.exit(1)
}
