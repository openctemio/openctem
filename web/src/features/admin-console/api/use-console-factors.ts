'use client'

/**
 * The administrator's own console factors: security keys and passkeys,
 * recovery codes, and the "require security keys" policy (RFC-078 §7). Every
 * call is about the signed-in administrator; the API keys each query on the
 * console session, never on an id from the client.
 */

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'
import {
  createCredential,
  getAssertion,
  type CreationOptionsJSON,
  type CredentialJSON,
  type PublicKeyEnvelope,
  type RequestOptionsJSON,
} from '../lib/webauthn'
import type { AdminIdentity } from '../types'

export const FACTORS_KEY = '/auth/factors'
export const MFA_POLICY_KEY = '/settings/console-mfa'

export interface ConsoleAuthenticator {
  id: string
  name: string
  aaguid?: string
  transports: string[]
  attachment?: string
  /** Backed up to a passkey provider (backup state). */
  synced: boolean
  sync_capable: boolean
  created_at: string
  last_used_at?: string
}

export interface ConsoleFactors {
  webauthn_enabled: boolean
  authenticators: ConsoleAuthenticator[]
  recovery_codes_left: number
  totp_enabled: boolean
  totp_allowed: boolean
  require_webauthn: boolean
  /** Until then an administrator with no key may use the authenticator app. */
  webauthn_grace_until?: string
  enrollment_required: boolean
  min_authenticators: number
  max_authenticators: number
}

export interface ConsoleMfaPolicy {
  require_webauthn: boolean
  /** Until then administrators with no key may use the authenticator app. */
  grace_until?: string
  version: number
  webauthn_enabled: boolean
}

/** The signed-in administrator's factors; `enabled` false skips the request. */
export function useConsoleFactors(enabled = true) {
  return useSWR<ConsoleFactors>(enabled ? FACTORS_KEY : null, adminFetcher, {
    revalidateOnFocus: false,
  })
}

export function useConsoleMfaPolicy() {
  return useSWR<ConsoleMfaPolicy>(MFA_POLICY_KEY, adminFetcher)
}

/** Super admin + step-up; 409 when the actor is not compliant or the version moved. */
export function saveConsoleMfaPolicy(input: { require_webauthn: boolean; version: number }) {
  return adminFetch<ConsoleMfaPolicy>(MFA_POLICY_KEY, { method: 'PUT', body: input })
}

// Sign-in (pending console session, the admin_mfa cookie).

/** Sign-in with a key: the API's options, the browser ceremony, the answer. */
export async function adminSignInWithKey(): Promise<AdminIdentity> {
  const opts = await adminFetch<PublicKeyEnvelope<RequestOptionsJSON>>(
    '/auth/webauthn/session/options',
    { method: 'POST' }
  )
  const credential = await getAssertion(opts.publicKey)
  return adminFetch<AdminIdentity>('/auth/webauthn/session', {
    method: 'POST',
    body: credential,
  })
}

export function adminSignInWithRecoveryCode(code: string) {
  return adminFetch<AdminIdentity>('/auth/recovery', { method: 'POST', body: { code } })
}

// Step-up with a key: opens this session's five-minute step-up window.

export async function adminStepUpWithKey(): Promise<void> {
  const opts = await adminFetch<PublicKeyEnvelope<RequestOptionsJSON>>(
    '/auth/step-up/webauthn/options',
    { method: 'POST' }
  )
  const credential = await getAssertion(opts.publicKey)
  await adminFetch<void>('/auth/step-up/webauthn', { method: 'POST', body: credential })
}

// Own keys and recovery codes.

/** Registers a key: the options take the step-up, the browser creates it. */
export async function registerSecurityKey(name: string): Promise<ConsoleAuthenticator> {
  const opts = await adminFetch<PublicKeyEnvelope<CreationOptionsJSON>>(
    '/auth/webauthn/credentials/options',
    { method: 'POST' }
  )
  const credential: CredentialJSON = await createCredential(opts.publicKey)
  return adminFetch<ConsoleAuthenticator>('/auth/webauthn/credentials', {
    method: 'POST',
    body: { name, credential },
  })
}

export function renameSecurityKey(id: string, name: string) {
  return adminFetch<ConsoleAuthenticator>(`/auth/webauthn/credentials/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: { name },
  })
}

/** Step-up; 409 WEBAUTHN_KEEP_REQUIRED below the policy's floor. */
export function removeSecurityKey(id: string) {
  return adminFetch<void>(`/auth/webauthn/credentials/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
}

/** Step-up; replaces every earlier code. The codes are shown once. */
export function generateRecoveryCodes() {
  return adminFetch<{ codes: string[] }>('/auth/recovery-codes', { method: 'POST' })
}
