import { describe, expect, it } from 'vitest'

import { sessionEndedMessage, sessionEndReason } from './session-ended'

describe('session end reasons', () => {
  it('maps refresh refusals to a reason', () => {
    expect(sessionEndReason('REFRESH_TOKEN_REUSED')).toBe('session_reused')
    expect(sessionEndReason('SESSION_EXPIRED')).toBe('session_expired')
    expect(sessionEndReason('REFRESH_TOKEN_EXPIRED')).toBe('session_expired')
    expect(sessionEndReason('REFRESH_TOKEN_REVOKED')).toBe('session_revoked')
    expect(sessionEndReason(undefined)).toBeUndefined()
    expect(sessionEndReason('SOMETHING_ELSE')).toBeUndefined()
  })

  it('shows a message only for known reasons', () => {
    expect(sessionEndedMessage('session_reused')?.key).toBe('auth.login.sessionEndedReused')
    expect(sessionEndedMessage('session_expired')?.key).toBe('auth.login.sessionExpired')
    expect(sessionEndedMessage('session_revoked')?.key).toBe('auth.login.sessionEndedRevoked')
    expect(sessionEndedMessage('<script>')).toBeUndefined()
    expect(sessionEndedMessage(null)).toBeUndefined()
  })
})
