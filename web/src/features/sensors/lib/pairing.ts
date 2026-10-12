/**
 * Pure helpers of the "Pair a sensor" dialog (api docs/rfcs/RFC-052 §4).
 */

import { ApiClientError } from '@/lib/api/error-handler'
import type { StepUpMethod } from '@/lib/api/sensor-pairing-hooks'

/** Crockford base32 alphabet of pairing codes (no I, L, O, U). */
const CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export const PAIRING_CODE_LENGTH = 8

/**
 * Normalises what the administrator typed the way the API does: case-folded,
 * dashes and spaces dropped, O read as 0 and I/L as 1. Null when it cannot
 * be a code (the API would answer the same uniform 404 anyway).
 */
export function normalizePairingCode(input: string): string | null {
  let out = ''
  for (const ch of input.toUpperCase()) {
    if (ch === '-' || ch === ' ' || ch === '\t') continue
    const c = ch === 'O' ? '0' : ch === 'I' || ch === 'L' ? '1' : ch
    if (!CODE_ALPHABET.includes(c)) return null
    out += c
  }
  return out.length === PAIRING_CODE_LENGTH ? out : null
}

/** "K7QM4ZTD" → "K7QM-4ZTD", as the sensor prints it. */
export function formatPairingCode(code: string): string {
  return code.length === PAIRING_CODE_LENGTH ? `${code.slice(0, 4)}-${code.slice(4)}` : code
}

/** "512 · tiger · violet · anchor" → { number: "512", words: [...] }. */
export function splitSas(sas: string | undefined): { number: string; words: string[] } | null {
  if (!sas) return null
  const parts = sas
    .split('·')
    .map((p) => p.trim())
    .filter(Boolean)
  if (parts.length < 2) return null
  return { number: parts[0], words: parts.slice(1) }
}

export function stepUpMethodOf(value: string | undefined): StepUpMethod {
  return value === 'totp' || value === 'password' || value === 'fresh_sign_in' ? value : 'password'
}

export interface GrantProfileOption {
  value: string
  label: string
  description: string
}

/**
 * Profiles an administrator may pick for a new sensor (RFC-052 §5.2). The
 * broad legacy grant is never offered: it exists only for sensors that
 * predate pairing. Every new sensor starts at trust level New whatever the
 * profile (passive work only, no credentials, no push ingest).
 */
export const GRANT_PROFILES: GrantProfileOption[] = [
  {
    value: 'internal-network-scanner',
    label: 'Internal network scanner',
    description: 'Scans and validation in the chosen zones; no credentials.',
  },
  {
    value: 'easm-external',
    label: 'External attack surface',
    description: 'Scans of internet-facing targets only; no private addresses, no credentials.',
  },
  {
    value: 'authenticated-scanner',
    label: 'Authenticated scanner',
    description: 'Like the internal scanner, and may receive scan credentials once trusted.',
  },
  {
    value: 'collector',
    label: 'Collector',
    description: 'Runs one connector; no target scanning.',
  },
  {
    value: 'ci-runner',
    label: 'CI runner',
    description: 'Code scanning only; no network targets.',
  },
  {
    value: 'endpoint-agent',
    label: 'Endpoint',
    description: 'Inspects its own host only; no network targets.',
  },
]

export const DEFAULT_GRANT_PROFILE = 'internal-network-scanner'

/**
 * The profile value sent to the API: `collector:<integration>` when an
 * integration is named. Integration names are lower-case tokens.
 */
export function grantProfileValue(profile: string, integration: string): string {
  if (profile !== 'collector') return profile
  const name = integration.trim().toLowerCase()
  return name ? `collector:${name}` : profile
}

export function validIntegrationName(name: string): boolean {
  return name.trim() === '' || /^[a-z0-9._-]{1,64}$/.test(name.trim().toLowerCase())
}

export const PAIRING_NOT_FOUND_MESSAGE = 'Code not found or expired'

/** A message for a failed pairing call, without leaking which case it was. */
export function pairingErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiClientError || (err && typeof err === 'object' && 'statusCode' in err)) {
    const e = err as { statusCode?: number; code?: string; message?: string }
    if (e.statusCode === 404) return PAIRING_NOT_FOUND_MESSAGE
    if (e.statusCode === 429) return 'Too many attempts. Wait a few minutes and try again.'
    if (e.code === 'STEP_UP_FAILED') return 'Re-authentication failed. Check the code or password.'
    if (e.code === 'STEP_UP_REQUIRED')
      return 'Re-authenticate to approve: enter your authenticator code or password.'
    if (e.code === 'FINGERPRINT_NOT_CONFIRMED')
      return 'Confirm that the fingerprint shown on the sensor matches before approving.'
    if (e.statusCode === 503) return 'Too many open pairing requests. Try again shortly.'
    if (e.statusCode === 403) return 'You do not have permission to do this.'
  }
  return fallback
}

/** Whole seconds until an ISO time (0 when past or unreadable). */
export function secondsUntil(iso: string | undefined, now: number): number {
  if (!iso) return 0
  const t = Date.parse(iso)
  return Number.isNaN(t) ? 0 : Math.max(0, Math.floor((t - now) / 1000))
}

export function formatCountdown(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${String(s).padStart(2, '0')}`
}
