import { describe, it, expect } from 'vitest'
import { adminPlaneSeparate, decidePlane } from '../admin-plane'

describe('admin plane gating', () => {
  it('changes nothing while the console shares the origin', () => {
    expect(decidePlane('/admin', null, false)).toBe('allow')
    expect(decidePlane('/findings', 'admin', false)).toBe('allow')
    expect(adminPlaneSeparate(undefined)).toBe(false)
    expect(adminPlaneSeparate('shared')).toBe(false)
    expect(adminPlaneSeparate('separate')).toBe(true)
  })

  it.each([
    ['/admin', 'allow'],
    ['/admin/organizations', 'allow'],
    ['/admin/login', 'allow'],
    ['/api/v1/admin/auth/login', 'allow'],
    ['/api/health', 'allow'],
    ['/', 'to-console'],
    ['/login', 'not-found'],
    ['/findings', 'not-found'],
    ['/api/v1/findings', 'not-found'],
    ['/api/auth/refresh', 'not-found'],
    ['/administrators', 'not-found'],
    ['/api/v1/administrators', 'not-found'],
  ])('on the console site, %s is %s', (path, want) => {
    expect(decidePlane(path, 'admin', true)).toBe(want)
  })

  it.each([
    ['/admin', 'not-found'],
    ['/admin/login', 'not-found'],
    ['/api/v1/admin/tenants', 'not-found'],
    ['/', 'allow'],
    ['/login', 'allow'],
    ['/api/v1/findings', 'allow'],
    ['/administrators', 'allow'],
  ])('on the main site, %s is %s', (path, want) => {
    expect(decidePlane(path, null, true)).toBe(want)
    // Any other value than "admin" is the main site.
    expect(decidePlane(path, 'Admin', true)).toBe(want)
  })

  it.each([
    ['/api/v1//admin/tenants', 'not-found'],
    ['//admin', 'not-found'],
    ['/x/../admin', 'not-found'],
    ['/admin/', 'not-found'],
    ['/%61dmin', 'not-found'],
    ['/api/v1%2Fadmin/tenants', 'not-found'],
    ['/api/v1/admin/../findings', 'allow'],
  ])('the main site reads %s the way the router does: %s', (path, want) => {
    expect(decidePlane(path, null, true)).toBe(want)
  })

  it.each([
    ['/admin//organizations', 'allow'],
    ['/admin/./login', 'allow'],
    ['/admin/../login', 'not-found'],
    ['/api/v1/admin/../findings', 'not-found'],
    ['/api/v1/admin/..%2f..%2ffindings', 'not-found'],
    ['/admin/%2e%2e/login', 'not-found'],
    ['//', 'to-console'],
  ])('the console site reads %s the way the router does: %s', (path, want) => {
    expect(decidePlane(path, 'admin', true)).toBe(want)
  })
})
