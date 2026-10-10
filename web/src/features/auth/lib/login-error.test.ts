import { describe, expect, it } from 'vitest'

import { en, vi } from '@/lib/i18n/dictionaries'
import { LOGIN_ERROR_CODES, loginErrorHref, loginErrorMessage } from './login-error'

describe('loginErrorMessage', () => {
  it.each(LOGIN_ERROR_CODES)('maps the known code %s to its own message', (code) => {
    expect(loginErrorMessage(code).key).toBe(`auth.loginError.${code}`)
  })

  it.each([
    'Your account is locked, call +1 555 0100',
    '<img src=x onerror=alert(1)>',
    'generic',
    '__proto__',
    '',
    null,
    undefined,
  ])('shows the generic message for anything else: %j', (param) => {
    expect(loginErrorMessage(param).key).toBe('auth.loginError.generic')
  })

  it('has en and vi text for every message', () => {
    for (const code of [...LOGIN_ERROR_CODES, 'generic']) {
      const key = `auth.loginError.${code}`
      expect((en as Record<string, string>)[key], key).toBeTruthy()
      expect((vi as Record<string, string>)[key], key).toBeTruthy()
    }
  })
})

describe('loginErrorHref', () => {
  it('carries only the code, plus extra parameters', () => {
    expect(loginErrorHref('callback_failed')).toBe('/login?error=callback_failed')
    expect(loginErrorHref('provider_error', { org: 'acme & co' })).toBe(
      '/login?error=provider_error&org=acme+%26+co'
    )
  })
})
