import { describe, expect, it } from 'vitest'
import { identityProviderLabel } from '../identity-provider-label'
import { getProviderLabel, SSO_PROVIDERS } from '@/features/sso/types/sso.types'

describe('identityProviderLabel', () => {
  it.each([
    ['google_workspace', 'Google Workspace'],
    ['entra_id', 'Microsoft Entra ID'],
    ['okta', 'Okta'],
    ['github', 'GitHub'],
    ['oidc', 'Single sign-on (OIDC)'],
    ['local', 'Email and password'],
  ])('%s -> %s', (id, label) => {
    expect(identityProviderLabel(id)).toBe(label)
  })

  it('treats a missing provider as an email and password account', () => {
    expect(identityProviderLabel(undefined)).toBe('Email and password')
  })

  it('never returns an unknown id as is', () => {
    expect(identityProviderLabel('ping_federate')).toBe('Ping federate')
  })

  it('is the source the SSO settings use', () => {
    for (const p of SSO_PROVIDERS) {
      expect(p.label).toBe(identityProviderLabel(p.value))
      expect(getProviderLabel(p.value)).toBe(identityProviderLabel(p.value))
    }
  })
})
