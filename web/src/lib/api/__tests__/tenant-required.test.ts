import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  isTenantRequired,
  resetTenantRequiredRouting,
  routeToWelcomeOnce,
} from '../tenant-required'

describe('401 TENANT_REQUIRED', () => {
  beforeEach(() => resetTenantRequiredRouting())

  it('recognizes only the 401 with that code', () => {
    expect(isTenantRequired({ statusCode: 401, code: 'TENANT_REQUIRED' })).toBe(true)
    expect(isTenantRequired({ statusCode: 401, code: 'UNAUTHORIZED' })).toBe(false)
    expect(isTenantRequired({ statusCode: 403, code: 'TENANT_REQUIRED' })).toBe(false)
    expect(isTenantRequired(undefined)).toBe(false)
  })

  it('routes to /welcome once, however many requests are refused', () => {
    const assign = vi.fn()
    expect(routeToWelcomeOnce({ pathname: '/findings', assign })).toBe(true)
    expect(routeToWelcomeOnce({ pathname: '/findings', assign })).toBe(false)
    expect(assign).toHaveBeenCalledTimes(1)
    expect(assign).toHaveBeenCalledWith('/welcome')
  })

  it.each(['/welcome', '/account', '/account/security'])(
    'never redirects from the account space (%s)',
    (pathname) => {
      const assign = vi.fn()
      expect(routeToWelcomeOnce({ pathname, assign })).toBe(false)
      expect(assign).not.toHaveBeenCalled()
    }
  )
})
