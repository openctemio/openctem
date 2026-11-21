/**
 * Pasted CI signing keys (api RFC-051, "Pasted signing keys"): the checks the
 * API makes when a trust configuration is saved, run in the browser so the
 * administrator sees what is wrong while pasting. The API stays the
 * authority.
 */

export type KeySource = 'fetch' | 'pasted'

export const MAX_SIGNING_KEYS_BYTES = 64 * 1024
export const MAX_SIGNING_KEYS = 10

/** Members that carry private or symmetric key material. */
const PRIVATE_PARAMS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const

export interface PastedKey {
  kid: string
  alg: 'RS256' | 'ES256'
}

/** A problem with the pasted document: an i18n key, its English text and values. */
export interface SigningKeysProblem {
  key: string
  fallback: string
  params?: Record<string, string | number>
}

export type SigningKeysCheck =
  { ok: true; keys: PastedKey[] } | { ok: false; problem: SigningKeysProblem }

const P = 'scans.ci.trust.signingKeys.error'

function problem(
  key: string,
  fallback: string,
  params?: Record<string, string | number>
): SigningKeysCheck {
  return { ok: false, problem: { key: `${P}.${key}`, fallback, params } }
}

/** Decoded byte length of a base64url value, or -1 when it is not one. */
function b64urlBytes(v: unknown): number {
  if (typeof v !== 'string' || v === '' || !/^[A-Za-z0-9_-]+$/.test(v)) return -1
  return Math.floor((v.length * 3) / 4)
}

/** Checks a pasted JWKS document and lists its keys. */
export function checkSigningKeys(doc: string): SigningKeysCheck {
  const text = doc.trim()
  if (!text) return problem('empty', 'Paste the signing keys document.')
  if (new TextEncoder().encode(doc).length > MAX_SIGNING_KEYS_BYTES)
    return problem('tooLarge', 'The document is larger than {max} KiB.', {
      max: MAX_SIGNING_KEYS_BYTES / 1024,
    })
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return problem('notJson', 'This is not valid JSON of the form {"keys":[...]}.')
  }
  const list =
    parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as { keys?: unknown }).keys
      : undefined
  if (!Array.isArray(list) || list.length === 0)
    return problem(
      'noKeys',
      'The document has no keys: paste the whole document, {"keys":[...]}, not a single key.'
    )
  if (list.length > MAX_SIGNING_KEYS)
    return problem('tooMany', 'The document has {count} keys; at most {max} are accepted.', {
      count: list.length,
      max: MAX_SIGNING_KEYS,
    })
  const keys: PastedKey[] = []
  for (const [i, raw] of list.entries()) {
    const n = i + 1
    if (!raw || typeof raw !== 'object' || Array.isArray(raw))
      return problem('notObject', 'Key {n} is not a JSON object.', { n })
    const k = raw as Record<string, unknown>
    const priv = PRIVATE_PARAMS.find((p) => p in k)
    if (priv)
      return problem(
        'private',
        'Key {n} carries private key material ("{param}"). Paste only the public keys the provider publishes.',
        { n, param: priv }
      )
    const kid = k.kid
    if (typeof kid !== 'string' || kid === '')
      return problem('noKid', 'Key {n} has no key id (kid).', { n })
    if (keys.some((x) => x.kid === kid))
      return problem('duplicateKid', 'The key id {kid} appears twice.', { kid })
    if (k.use !== undefined && k.use !== 'sig')
      return problem('notSigning', 'Key {n} is not a signing key (use must be "sig").', { n })
    if (k.kty === 'RSA') {
      if (k.alg !== undefined && k.alg !== 'RS256')
        return problem('rsaAlg', 'Key {n}: an RSA key must be RS256.', { n })
      if (b64urlBytes(k.n) < 256 || b64urlBytes(k.e) <= 0)
        return problem('rsaKey', 'Key {n} is not an RSA public key of at least 2048 bits.', { n })
      keys.push({ kid, alg: 'RS256' })
    } else if (k.kty === 'EC') {
      if (k.alg !== undefined && k.alg !== 'ES256')
        return problem('ecAlg', 'Key {n}: an EC key must be ES256.', { n })
      const x = b64urlBytes(k.x)
      const y = b64urlBytes(k.y)
      if (k.crv !== 'P-256' || x <= 0 || x > 32 || y <= 0 || y > 32)
        return problem('ecKey', 'Key {n} is not a P-256 public key.', { n })
      keys.push({ kid, alg: 'ES256' })
    } else {
      return problem('keyType', 'Key {n}: only RSA and EC P-256 keys are accepted.', { n })
    }
  }
  return { ok: true, keys: keys.sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0)) }
}
