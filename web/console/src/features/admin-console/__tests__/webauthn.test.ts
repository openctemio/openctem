import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  base64urlToBuffer,
  bufferToBase64url,
  credentialToJSON,
  getAssertion,
  parseCreationOptions,
  parseRequestOptions,
  WebAuthnCancelledError,
  WebAuthnUnsupportedError,
} from '../lib/webauthn'

const bytes = (...b: number[]) => new Uint8Array(b).buffer

function stubWebAuthn(get: (...a: unknown[]) => unknown, statics: Record<string, unknown> = {}) {
  const PKC = Object.assign(function PublicKeyCredential() {}, statics)
  vi.stubGlobal('PublicKeyCredential', PKC)
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: { get: vi.fn(get), create: vi.fn() },
  })
}

describe('base64url', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('round-trips bytes without padding and with the URL alphabet', () => {
    const raw = bytes(0xfb, 0xff, 0xbf, 0x00, 0x01)
    const enc = bufferToBase64url(raw)
    expect(enc).toBe('-_-_AAE')
    expect(enc).not.toMatch(/[+/=]/)
    expect(new Uint8Array(base64urlToBuffer(enc))).toEqual(new Uint8Array(raw))
  })

  it('decodes every padding length', () => {
    for (const s of ['', 'AA', 'AAE', 'AAEC', 'AAECAw']) {
      expect(bufferToBase64url(base64urlToBuffer(s))).toBe(s)
    }
  })

  it('encodes a view on part of a buffer', () => {
    const view = new Uint8Array([9, 1, 2, 9]).subarray(1, 3)
    expect(bufferToBase64url(view)).toBe('AQI')
  })
})

describe('options and credentials without the browser JSON helpers', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('converts request options', () => {
    stubWebAuthn(() => null)
    const o = parseRequestOptions({
      challenge: 'AQID',
      rpId: 'admin.example.com',
      userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: 'BAU', transports: ['usb'] }],
    })
    expect(new Uint8Array(o.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]))
    expect(o.userVerification).toBe('required')
    const cred = o.allowCredentials![0]
    expect(new Uint8Array(cred.id as ArrayBuffer)).toEqual(new Uint8Array([4, 5]))
    expect(cred.transports).toEqual(['usb'])
  })

  it('converts creation options (user id and excluded keys are binary)', () => {
    stubWebAuthn(() => null)
    const o = parseCreationOptions({
      rp: { id: 'admin.example.com', name: 'Console' },
      user: { id: 'AQ', name: 'a@example.com', displayName: 'A' },
      challenge: 'AgM',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ type: 'public-key', id: 'BA' }],
    })
    expect(new Uint8Array(o.user.id as ArrayBuffer)).toEqual(new Uint8Array([1]))
    expect(new Uint8Array(o.excludeCredentials![0].id as ArrayBuffer)).toEqual(new Uint8Array([4]))
  })

  it('uses the browser helper when there is one', () => {
    const parsed = { challenge: bytes(7) }
    const parseRequestOptionsFromJSON = vi.fn(() => parsed)
    stubWebAuthn(() => null, { parseRequestOptionsFromJSON })
    expect(parseRequestOptions({ challenge: 'Bw' })).toBe(parsed)
    expect(parseRequestOptionsFromJSON).toHaveBeenCalledWith({ challenge: 'Bw' })
  })

  it('serialises an assertion', () => {
    const json = credentialToJSON({
      id: 'abc',
      rawId: bytes(1, 2),
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      response: {
        clientDataJSON: bytes(3),
        authenticatorData: bytes(4),
        signature: bytes(5),
        userHandle: bytes(6),
      },
      getClientExtensionResults: () => ({}),
    } as unknown as Credential)
    expect(json).toEqual({
      id: 'abc',
      rawId: 'AQI',
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: 'Aw',
        authenticatorData: 'BA',
        signature: 'BQ',
        userHandle: 'Bg',
      },
    })
  })

  it('prefers credential.toJSON()', () => {
    const toJSON = vi.fn(() => ({ id: 'native' }))
    expect(credentialToJSON({ toJSON } as unknown as Credential)).toEqual({ id: 'native' })
  })
})

describe('getAssertion', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('maps a dismissed or timed-out prompt to a cancel', async () => {
    stubWebAuthn(() => Promise.reject(new DOMException('no', 'NotAllowedError')))
    await expect(getAssertion({ challenge: 'AQ' })).rejects.toBeInstanceOf(WebAuthnCancelledError)
  })

  it('refuses when the browser has no WebAuthn', async () => {
    vi.stubGlobal('PublicKeyCredential', undefined)
    await expect(getAssertion({ challenge: 'AQ' })).rejects.toBeInstanceOf(WebAuthnUnsupportedError)
  })
})
