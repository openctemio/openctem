import { describe, expect, it, beforeEach } from 'vitest'
import { env } from '@/lib/env'
import { shareableLink, withOrg, withoutOrgParam } from '../org-link'

function setTenantCookie(value: string | null) {
  document.cookie = value
    ? `${env.cookies.tenant}=${encodeURIComponent(value)}; path=/`
    : `${env.cookies.tenant}=; path=/; max-age=0`
}

const ORG = '6f1c2a9e-3b7d-4c55-9a0e-1d2f3a4b5c6d'

describe('withOrg', () => {
  it('adds the org to a detail path', () => {
    expect(withOrg('/emerging-threats/abc', ORG)).toBe(`/emerging-threats/abc?org=${ORG}`)
  })
  it('keeps the query and the fragment, and replaces an org already there', () => {
    expect(withOrg('/findings?sort=-priority&org=old#top', ORG)).toBe(
      `/findings?sort=-priority&org=${ORG}#top`
    )
  })
  it('works on an absolute link', () => {
    expect(withOrg('https://ctem.example.com/findings/1', ORG)).toBe(
      `https://ctem.example.com/findings/1?org=${ORG}`
    )
  })
  it('leaves the link alone without an org', () => {
    expect(withOrg('/findings/1', null)).toBe('/findings/1')
    expect(withOrg('/findings/1', '  ')).toBe('/findings/1')
  })
})

describe('withoutOrgParam', () => {
  it('drops only the org parameter', () => {
    expect(withoutOrgParam(`?org=${ORG}&tab=evidence`)).toBe('?tab=evidence')
    expect(withoutOrgParam(`?org=${ORG}`)).toBe('')
    expect(withoutOrgParam('')).toBe('')
  })
})

describe('shareableLink', () => {
  beforeEach(() => setTenantCookie(null))
  it('ignores a malformed tenant cookie', () => {
    setTenantCookie('not json')
    expect(shareableLink('/findings/1')).toBe(`${window.location.origin}/findings/1`)
  })
  it('names the selected organization', () => {
    setTenantCookie(JSON.stringify({ id: ORG, slug: 'acme', name: 'Acme', role: 'owner' }))
    expect(shareableLink('/findings/1')).toBe(`${window.location.origin}/findings/1?org=${ORG}`)
  })
  it('is a plain link when no organization is selected', () => {
    setTenantCookie(null)
    expect(shareableLink('/findings/1')).toBe(`${window.location.origin}/findings/1`)
  })
})
