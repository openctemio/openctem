import { describe, expect, it } from 'vitest'
import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { checkSigningKeys, MAX_SIGNING_KEYS_BYTES } from '../lib/signing-keys'
import {
  CITrustSigningKeys,
  CITrustSigningKeysSummary,
  signingKeysReady,
} from '../components/ci-trust-signing-keys'
import type { KeySource } from '../lib/signing-keys'
import type { CITrustConfig } from '../types'

// Base64url values of the right sizes (the API checks the key itself).
const N = 'A'.repeat(342) // 256 bytes: a 2048-bit modulus
const X = 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU'
const Y = 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0'
const rsa = (kid: string, extra: Record<string, unknown> = {}) => ({
  kty: 'RSA',
  kid,
  use: 'sig',
  alg: 'RS256',
  n: N,
  e: 'AQAB',
  ...extra,
})
const ec = (kid: string, extra: Record<string, unknown> = {}) => ({
  kty: 'EC',
  kid,
  crv: 'P-256',
  x: X,
  y: Y,
  ...extra,
})
const doc = (...keys: unknown[]) => JSON.stringify({ keys })

describe('checkSigningKeys', () => {
  it('lists the kids and algorithms of a valid document', () => {
    expect(checkSigningKeys(doc(rsa('b'), ec('a')))).toEqual({
      ok: true,
      keys: [
        { kid: 'a', alg: 'ES256' },
        { kid: 'b', alg: 'RS256' },
      ],
    })
    // alg and use may be absent.
    expect(checkSigningKeys(doc({ kty: 'RSA', kid: 'k', n: N, e: 'AQAB' })).ok).toBe(true)
  })

  const refused: [string, string, string][] = [
    ['empty', '  ', 'empty'],
    ['not json', '-----BEGIN PUBLIC KEY-----', 'notJson'],
    ['a single key, not a set', JSON.stringify(rsa('k')), 'noKeys'],
    ['no keys', '{"keys":[]}', 'noKeys'],
    ['too many keys', doc(...Array.from({ length: 11 }, (_, i) => rsa(`k${i}`))), 'tooMany'],
    ['too large', `{"keys":[],"x":"${'a'.repeat(MAX_SIGNING_KEYS_BYTES)}"}`, 'tooLarge'],
    ['private d', doc(rsa('k', { d: 'AQAB' })), 'private'],
    ['private p', doc(rsa('k', { p: 'AQAB' })), 'private'],
    ['private q', doc(rsa('k', { q: 'AQAB' })), 'private'],
    ['private dp', doc(rsa('k', { dp: 'AQAB' })), 'private'],
    ['private dq', doc(rsa('k', { dq: 'AQAB' })), 'private'],
    ['private qi', doc(rsa('k', { qi: 'AQAB' })), 'private'],
    ['symmetric k', doc({ kty: 'oct', kid: 'h', k: 'c2VjcmV0' }), 'private'],
    ['no kid', doc(rsa('')), 'noKid'],
    ['duplicate kid', doc(rsa('k'), ec('k')), 'duplicateKid'],
    ['use enc', doc(rsa('k', { use: 'enc' })), 'notSigning'],
    ['rsa RS512', doc(rsa('k', { alg: 'RS512' })), 'rsaAlg'],
    ['rsa too small', doc(rsa('k', { n: 'A'.repeat(171) })), 'rsaKey'],
    ['ec ES384', doc(ec('k', { alg: 'ES384' })), 'ecAlg'],
    ['ec P-384', doc(ec('k', { crv: 'P-384' })), 'ecKey'],
    ['okp key', doc({ kty: 'OKP', kid: 'o', crv: 'Ed25519', x: X }), 'keyType'],
  ]
  it.each(refused)('refuses %s', (_name, input, key) => {
    const r = checkSigningKeys(input)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.problem.key).toBe(`scans.ci.trust.signingKeys.error.${key}`)
  })

  it('is ready in fetch mode, and in pasted mode only with a valid document', () => {
    expect(signingKeysReady('fetch', '')).toBe(true)
    expect(signingKeysReady('pasted', '')).toBe(false)
    expect(signingKeysReady('pasted', doc(rsa('k', { d: 'x' })))).toBe(false)
    expect(signingKeysReady('pasted', doc(rsa('k')))).toBe(true)
  })
})

function Harness({ saved }: { saved?: CITrustConfig }) {
  const [source, setSource] = useState<KeySource>('fetch')
  const [keys, setKeys] = useState('')
  return (
    <CITrustSigningKeys
      provider="gitlab"
      source={source}
      keys={keys}
      onSourceChange={setSource}
      onKeysChange={setKeys}
      saved={saved}
    />
  )
}

describe('CITrustSigningKeys', () => {
  it('fetches by default and shows the paste box only for pasted keys', async () => {
    render(<Harness />)
    expect(screen.getByRole('radio', { name: 'Fetch from the provider' })).toBeChecked()
    expect(screen.queryByLabelText('Keys (JWKS document)')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('radio', { name: 'Use keys I paste' }))
    expect(screen.getByLabelText('Keys (JWKS document)')).toBeInTheDocument()
    expect(
      screen.getByText(
        'Open https://<your GitLab>/oauth/discovery/keys and paste the whole document (all keys).'
      )
    ).toBeInTheDocument()
  })

  it('names the problem inline and lists the keys of a valid document', async () => {
    render(<Harness />)
    await userEvent.click(screen.getByRole('radio', { name: 'Use keys I paste' }))
    const box = screen.getByLabelText('Keys (JWKS document)')
    await userEvent.click(box)
    await userEvent.paste(doc(rsa('k1', { d: 'AQAB' })))
    expect(screen.getByTestId('ci-signing-keys-error')).toHaveTextContent(
      /private key material \("d"\)/
    )
    expect(box).toHaveAttribute('aria-invalid', 'true')
    await userEvent.clear(box)
    await userEvent.paste(doc(rsa('k1'), ec('k2')))
    expect(screen.queryByTestId('ci-signing-keys-error')).not.toBeInTheDocument()
    expect(screen.getByTestId('ci-signing-keys-found')).toHaveTextContent('k1 (RS256), k2 (ES256)')
  })
})

describe('CITrustSigningKeysSummary', () => {
  const base = {
    id: 'c1',
    name: 'self-managed',
    provider: 'gitlab',
    key_source: 'pasted',
    signing_key_list: [
      { kid: 'k1', alg: 'RS256' },
      { kid: 'k2', alg: 'ES256' },
    ],
    signing_keys_updated_at: new Date(Date.now() - 3_600_000).toISOString(),
  } as unknown as CITrustConfig

  it('shows the kids, algorithms, paste date and last used key', () => {
    render(<CITrustSigningKeysSummary config={{ ...base, last_key_id: 'k2' } as CITrustConfig} />)
    const summary = screen.getByTestId('ci-signing-keys-summary')
    expect(summary).toHaveTextContent('Pasted signing keys')
    expect(summary).toHaveTextContent('k1 (RS256), k2 (ES256)')
    expect(summary).toHaveTextContent('Last used key k2')
  })

  it('says when no token used the keys yet, and is absent for fetched keys', () => {
    const { rerender } = render(<CITrustSigningKeysSummary config={base} />)
    expect(screen.getByTestId('ci-signing-keys-summary')).toHaveTextContent(
      'No token verified with these keys yet'
    )
    rerender(
      <CITrustSigningKeysSummary config={{ ...base, key_source: 'fetch' } as CITrustConfig} />
    )
    expect(screen.queryByTestId('ci-signing-keys-summary')).not.toBeInTheDocument()
  })
})
