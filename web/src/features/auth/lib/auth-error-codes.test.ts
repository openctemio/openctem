import { readFileSync } from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import { getDictionary, translate } from '@/lib/i18n'
import {
  AUTH_ERROR_CODES,
  authErrorText,
  describeAuthCode,
  loginErrorCodeFor,
} from './auth-error-codes'
import { LOGIN_ERROR_CODES } from './login-error'

const tFor = (lang: 'en' | 'vi') => {
  const dict = getDictionary(lang)
  return (key: string, fallback?: string, vars?: Record<string, string | number>) =>
    translate(dict, key, fallback, vars)
}

describe('describeAuthCode', () => {
  it.each(['en', 'vi'] as const)('has text for every code in %s', (lang) => {
    const t = tFor(lang)
    for (const code of AUTH_ERROR_CODES) {
      const text = describeAuthCode(code, t)
      expect(text, `${lang} ${code}`).toBeTruthy()
      expect(text, `${lang} ${code} must not be the key`).not.toBe(`errors.auth.${code}`)
      expect(text).not.toMatch(/ — | · |–/)
      expect(text).not.toMatch(/\bteam\b/i)
    }
  })

  it('words the Vietnamese text differently from the English one', () => {
    const en = tFor('en')
    const vi = tFor('vi')
    for (const code of AUTH_ERROR_CODES) {
      expect(describeAuthCode(code, vi), code).not.toBe(describeAuthCode(code, en))
    }
  })

  // The rate limiter answers sign-in with RATE_LIMIT_EXCEEDED (429). The form
  // said only "Sign-in failed" for it, which reads like a wrong password.
  it('words a 429 on sign-in as a wait, not as a failed sign-in', () => {
    expect(authErrorText('RATE_LIMIT_EXCEEDED', tFor('en'), 'Sign-in failed')).toBe(
      'Too many attempts. Wait a minute and try again.'
    )
  })

  it.each(['Your access is waiting', '', null, undefined, '__proto__', 'unknown_code', 'INVALID'])(
    'is undefined for a value that is not a known code: %j',
    (code) => {
      expect(describeAuthCode(code as string, tFor('en'))).toBeUndefined()
    }
  )

  it('never uses the server sentence: a known code gives the console text, an unknown one the fallback', () => {
    const t = tFor('vi')
    expect(authErrorText('SSO_AWAITING_APPROVAL', t, 'fallback')).toBe(
      describeAuthCode('SSO_AWAITING_APPROVAL', t)
    )
    expect(authErrorText('NOT_A_CODE', t, 'fallback')).toBe('fallback')
    expect(authErrorText(undefined, t, 'fallback')).toBe('fallback')
  })
})

describe('loginErrorCodeFor', () => {
  it('maps every refusal a person can act on to its own login code', () => {
    expect(loginErrorCodeFor('SSO_AWAITING_APPROVAL')).toBe('awaiting_approval')
    expect(loginErrorCodeFor('SSO_NOT_A_MEMBER')).toBe('not_member')
    expect(loginErrorCodeFor('LIMIT_REACHED')).toBe('no_seat')
    expect(loginErrorCodeFor('SSO_DOMAIN_NOT_ALLOWED')).toBe('domain_not_allowed')
    expect(loginErrorCodeFor('ACCOUNT_LINK_REQUIRED')).toBe('link_required')
    expect(loginErrorCodeFor('SSO_REQUIRED')).toBe('sso_required')
    expect(loginErrorCodeFor('SSO_DIFFERENT_METHOD')).toBe('different_method')
    expect(loginErrorCodeFor('USE_ADMIN_CONSOLE')).toBe('use_console')
    expect(loginErrorCodeFor('EMAIL_UNVERIFIED_AT_IDP')).toBe('email_unverified_at_idp')
    expect(loginErrorCodeFor('ORGANIZATION_SUSPENDED')).toBe('organization_unavailable')
    expect(loginErrorCodeFor('OAUTH_ACCOUNT_EXISTS')).toBe('account_exists')
  })

  it.each([undefined, null, '', 'SSO_EXCHANGE_FAILED', 'constructor'])(
    'is the generic callback failure for %j',
    (code) => {
      expect(loginErrorCodeFor(code)).toBe('callback_failed')
    }
  )
})

// The API table (auth_error_codes.go) and this list must not drift.
describe('API table in step with the web codes', () => {
  const goFile = readFileSync(
    path.resolve(__dirname, '../../../../../api/internal/infra/http/handler/auth_error_codes.go'),
    'utf8'
  )
  const tableStart = goFile.indexOf('var authErrorTable')
  const table = goFile.slice(tableStart)
  const consts = goFile.slice(0, tableStart)

  it('every code constant of the table has web text', () => {
    const codes = [...consts.matchAll(/apierror\.Code = "([A-Z_]+)"/g)].map((m) => m[1])
    expect(codes.length).toBeGreaterThan(40)
    for (const code of codes) expect(AUTH_ERROR_CODES, code).toContain(code)
  })

  it('every login code the API redirects with is one the login page knows', () => {
    const logins = [...table.matchAll(/, "([a-z_]+)"\},?\n/g)].map((m) => m[1])
    expect(logins.length).toBeGreaterThan(8)
    for (const login of logins)
      expect(LOGIN_ERROR_CODES as readonly string[], login).toContain(login)
    expect(LOGIN_ERROR_CODES as readonly string[]).toContain('saml_failed')
  })
})
