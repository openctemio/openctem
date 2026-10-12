import { describe, expect, it } from 'vitest'

import { ApiClientError } from '@/lib/api/error-handler'

import {
  GRANT_PROFILES,
  formatCountdown,
  formatPairingCode,
  grantProfileValue,
  normalizePairingCode,
  pairingErrorMessage,
  splitSas,
  stepUpMethodOf,
  validIntegrationName,
} from '../pairing'

describe('pairing helpers', () => {
  it('normalises codes the way the API does', () => {
    expect(normalizePairingCode('k7qm-4ztd')).toBe('K7QM4ZTD')
    expect(normalizePairingCode(' K7QM 4ZTD ')).toBe('K7QM4ZTD')
    expect(normalizePairingCode('O1IL-0000')).toBe('01110000')
    expect(normalizePairingCode('K7QM-4ZT')).toBeNull()
    expect(normalizePairingCode('K7QM-4ZTU')).toBeNull() // U is not in the alphabet
    expect(formatPairingCode('K7QM4ZTD')).toBe('K7QM-4ZTD')
  })

  it('splits the SAS into the number and the words', () => {
    expect(splitSas('512 · tiger · violet · anchor')).toEqual({
      number: '512',
      words: ['tiger', 'violet', 'anchor'],
    })
    expect(splitSas('')).toBeNull()
    expect(splitSas(undefined)).toBeNull()
  })

  it('offers only the selectable profiles, never the legacy broad grant', () => {
    expect(GRANT_PROFILES.map((p) => p.value)).toEqual([
      'internal-network-scanner',
      'easm-external',
      'authenticated-scanner',
      'collector',
      'ci-runner',
      'endpoint-agent',
    ])
  })

  it('names the collector integration', () => {
    expect(grantProfileValue('collector', ' GitHub ')).toBe('collector:github')
    expect(grantProfileValue('collector', '')).toBe('collector')
    expect(grantProfileValue('easm-external', 'x')).toBe('easm-external')
    expect(validIntegrationName('github')).toBe(true)
    expect(validIntegrationName('bad name')).toBe(false)
  })

  it('maps errors without telling the cases of a miss apart', () => {
    expect(pairingErrorMessage(new ApiClientError('x', 'NOT_FOUND', 404), 'f')).toBe(
      'Code not found or expired'
    )
    expect(pairingErrorMessage(new ApiClientError('x', 'RATE_LIMIT_EXCEEDED', 429), 'f')).toMatch(
      /too many/i
    )
    expect(pairingErrorMessage(new ApiClientError('x', 'STEP_UP_FAILED', 403), 'f')).toMatch(
      /re-authentication failed/i
    )
    expect(pairingErrorMessage(new Error('boom'), 'fallback')).toBe('fallback')
  })

  it('defaults an unknown step-up method to the password', () => {
    expect(stepUpMethodOf('totp')).toBe('totp')
    expect(stepUpMethodOf('fresh_sign_in')).toBe('fresh_sign_in')
    expect(stepUpMethodOf(undefined)).toBe('password')
    expect(formatCountdown(125)).toBe('2:05')
  })
})
