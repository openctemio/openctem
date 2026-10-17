/**
 * Browser side of the console's security-key ceremonies (RFC-078 §7). The API
 * sends WebAuthn options as JSON (binary fields base64url) and takes the
 * credential back as JSON. Browsers that have the JSON helpers
 * (PublicKeyCredential.parse*OptionsFromJSON, credential.toJSON) use them; the
 * others get the same conversion here.
 *
 * The browser binds every assertion to the console origin; nothing here is a
 * security boundary, the API verifies each answer.
 */

/** Base64url string as the API sends binary fields. */
type B64 = string

interface CredentialDescriptorJSON {
  type: string
  id: B64
  transports?: string[]
}

export interface RequestOptionsJSON {
  challenge: B64
  timeout?: number
  rpId?: string
  allowCredentials?: CredentialDescriptorJSON[]
  userVerification?: string
  extensions?: Record<string, unknown>
  hints?: string[]
}

export interface CreationOptionsJSON {
  rp: { id?: string; name: string }
  user: { id: B64; name: string; displayName: string }
  challenge: B64
  pubKeyCredParams: { type: string; alg: number }[]
  timeout?: number
  excludeCredentials?: CredentialDescriptorJSON[]
  authenticatorSelection?: Record<string, unknown>
  attestation?: string
  extensions?: Record<string, unknown>
  hints?: string[]
}

/** What the API's option endpoints answer. */
export interface PublicKeyEnvelope<T> {
  publicKey: T
}

/** The credential as the API takes it (PublicKeyCredential.toJSON()). */
export type CredentialJSON = Record<string, unknown>

/** The user dismissed the browser prompt, or it timed out. */
export class WebAuthnCancelledError extends Error {
  constructor() {
    super('The security key prompt was cancelled or timed out')
    this.name = 'WebAuthnCancelledError'
  }
}

/** The browser cannot run a security-key ceremony at all. */
export class WebAuthnUnsupportedError extends Error {
  constructor() {
    super('This browser does not support security keys or passkeys')
    this.name = 'WebAuthnUnsupportedError'
  }
}

export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator !== 'undefined' &&
    !!navigator.credentials
  )
}

export function base64urlToBuffer(value: string): ArrayBuffer {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
  const bin = atob(padded)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

export function bufferToBase64url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

interface PKCStatic {
  parseRequestOptionsFromJSON?: (o: RequestOptionsJSON) => PublicKeyCredentialRequestOptions
  parseCreationOptionsFromJSON?: (o: CreationOptionsJSON) => PublicKeyCredentialCreationOptions
}

function pkc(): PKCStatic {
  return window.PublicKeyCredential as unknown as PKCStatic
}

function descriptors(
  list?: CredentialDescriptorJSON[]
): PublicKeyCredentialDescriptor[] | undefined {
  return list?.map((d) => ({
    type: d.type as PublicKeyCredentialType,
    id: base64urlToBuffer(d.id),
    ...(d.transports ? { transports: d.transports as AuthenticatorTransport[] } : {}),
  }))
}

export function parseRequestOptions(o: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  const native = pkc().parseRequestOptionsFromJSON
  if (typeof native === 'function') return native.call(window.PublicKeyCredential, o)
  return {
    challenge: base64urlToBuffer(o.challenge),
    ...(o.timeout !== undefined ? { timeout: o.timeout } : {}),
    ...(o.rpId ? { rpId: o.rpId } : {}),
    ...(o.allowCredentials ? { allowCredentials: descriptors(o.allowCredentials) } : {}),
    ...(o.userVerification
      ? { userVerification: o.userVerification as UserVerificationRequirement }
      : {}),
    ...(o.extensions ? { extensions: o.extensions as AuthenticationExtensionsClientInputs } : {}),
  }
}

export function parseCreationOptions(o: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  const native = pkc().parseCreationOptionsFromJSON
  if (typeof native === 'function') return native.call(window.PublicKeyCredential, o)
  return {
    rp: o.rp,
    user: { ...o.user, id: base64urlToBuffer(o.user.id) },
    challenge: base64urlToBuffer(o.challenge),
    pubKeyCredParams: o.pubKeyCredParams as PublicKeyCredentialParameters[],
    ...(o.timeout !== undefined ? { timeout: o.timeout } : {}),
    ...(o.excludeCredentials ? { excludeCredentials: descriptors(o.excludeCredentials) } : {}),
    ...(o.authenticatorSelection
      ? { authenticatorSelection: o.authenticatorSelection as AuthenticatorSelectionCriteria }
      : {}),
    ...(o.attestation ? { attestation: o.attestation as AttestationConveyancePreference } : {}),
    ...(o.extensions ? { extensions: o.extensions as AuthenticationExtensionsClientInputs } : {}),
  }
}

interface ResponseLike {
  clientDataJSON: ArrayBuffer
  authenticatorData?: ArrayBuffer
  signature?: ArrayBuffer
  userHandle?: ArrayBuffer | null
  attestationObject?: ArrayBuffer
  getTransports?: () => string[]
  getPublicKeyAlgorithm?: () => number
  getPublicKey?: () => ArrayBuffer | null
  getAuthenticatorData?: () => ArrayBuffer
}

interface CredentialLike {
  id: string
  rawId: ArrayBuffer
  type: string
  authenticatorAttachment?: string | null
  response: ResponseLike
  getClientExtensionResults?: () => Record<string, unknown>
  toJSON?: () => CredentialJSON
}

/** The credential in the JSON form the API reads. */
export function credentialToJSON(cred: Credential): CredentialJSON {
  const c = cred as unknown as CredentialLike
  if (typeof c.toJSON === 'function') return c.toJSON()
  const r = c.response
  const response: Record<string, unknown> = { clientDataJSON: bufferToBase64url(r.clientDataJSON) }
  if (r.attestationObject) {
    response.attestationObject = bufferToBase64url(r.attestationObject)
    if (typeof r.getTransports === 'function') response.transports = r.getTransports()
    if (typeof r.getPublicKeyAlgorithm === 'function')
      response.publicKeyAlgorithm = r.getPublicKeyAlgorithm()
    const pk = typeof r.getPublicKey === 'function' ? r.getPublicKey() : null
    if (pk) response.publicKey = bufferToBase64url(pk)
    const ad = typeof r.getAuthenticatorData === 'function' ? r.getAuthenticatorData() : null
    if (ad) response.authenticatorData = bufferToBase64url(ad)
  } else {
    if (r.authenticatorData) response.authenticatorData = bufferToBase64url(r.authenticatorData)
    if (r.signature) response.signature = bufferToBase64url(r.signature)
    if (r.userHandle) response.userHandle = bufferToBase64url(r.userHandle)
  }
  return {
    id: c.id,
    rawId: bufferToBase64url(c.rawId),
    type: c.type,
    response,
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    clientExtensionResults:
      typeof c.getClientExtensionResults === 'function' ? c.getClientExtensionResults() : {},
  }
}

/** Maps the browser's refusal of a ceremony: cancel and timeout read the same. */
function mapCeremonyError(err: unknown): unknown {
  if (err instanceof DOMException && (err.name === 'NotAllowedError' || err.name === 'AbortError'))
    return new WebAuthnCancelledError()
  return err
}

/** Runs navigator.credentials.get for API request options. */
export async function getAssertion(options: RequestOptionsJSON): Promise<CredentialJSON> {
  if (!isWebAuthnSupported()) throw new WebAuthnUnsupportedError()
  let cred: Credential | null
  try {
    cred = await navigator.credentials.get({ publicKey: parseRequestOptions(options) })
  } catch (err) {
    throw mapCeremonyError(err)
  }
  if (!cred) throw new WebAuthnCancelledError()
  return credentialToJSON(cred)
}

/** Runs navigator.credentials.create for API creation options. */
export async function createCredential(options: CreationOptionsJSON): Promise<CredentialJSON> {
  if (!isWebAuthnSupported()) throw new WebAuthnUnsupportedError()
  let cred: Credential | null
  try {
    cred = await navigator.credentials.create({ publicKey: parseCreationOptions(options) })
  } catch (err) {
    throw mapCeremonyError(err)
  }
  if (!cred) throw new WebAuthnCancelledError()
  return credentialToJSON(cred)
}

export function isWebAuthnCancelled(err: unknown): boolean {
  return err instanceof WebAuthnCancelledError
}
