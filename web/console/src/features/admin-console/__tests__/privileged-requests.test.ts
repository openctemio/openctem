/**
 * The requests behind the console's privileged confirmations: the code typed
 * in the dialog rides in the step-up header (the route confirms it once, no
 * second prompt), the reason in the body, and every write carries the CSRF
 * token. The catalog routes also check the code in the body, and stream the
 * bundle last, so the reason and the code come first in the form.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ADMIN_STEP_UP_HEADER, setAdminCsrfToken } from '@console/lib/admin-api/client'
import {
  confirmBreakGlassTest,
  resetAdminCredentials,
  unbindAdminIdP,
  updateAdminUser,
} from '../api/use-admin-users'
import { importCatalogBundle, revokeCatalogVersion } from '../api/use-content-catalog'

const fetchMock = vi.fn()
const call = (i = 0) => {
  const [url, init] = fetchMock.mock.calls[i] as [string, RequestInit]
  return { url, init, headers: init.headers as Record<string, string> }
}
const proof = { reason: 'Left the company, ticket 77', totp_code: '123456' }

describe('privileged console requests', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    setAdminCsrfToken('csrf-123')
    fetchMock.mockImplementation(async () => new Response('{}', { status: 200 }))
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('a roster change sends the reason in the body and the code in the step-up header', async () => {
    await updateAdminUser('a2', { role: 'super_admin' }, proof)
    const { url, init, headers } = call()
    expect(url).toBe('/api/v1/admin/users/a2')
    expect(init.method).toBe('PATCH')
    expect(JSON.parse(init.body as string)).toEqual({
      role: 'super_admin',
      reason: 'Left the company, ticket 77',
    })
    expect(headers[ADMIN_STEP_UP_HEADER]).toBe('123456')
    expect(headers['X-CSRF-Token']).toBe('csrf-123')
  })

  it.each([
    ['reset-credentials', () => resetAdminCredentials('a2', proof), 'POST'],
    ['break-glass-test', () => confirmBreakGlassTest('a2', proof), 'POST'],
    ['idp-binding', () => unbindAdminIdP('a2', proof), 'DELETE'],
  ])('%s carries the reason and the code', async (path, run, method) => {
    await run()
    const { url, init, headers } = call()
    expect(url).toBe(`/api/v1/admin/users/a2/${path}`)
    expect(init.method).toBe(method)
    expect(JSON.parse(init.body as string)).toEqual({ reason: 'Left the company, ticket 77' })
    expect(headers[ADMIN_STEP_UP_HEADER]).toBe('123456')
    expect(headers['X-CSRF-Token']).toBe('csrf-123')
  })

  it('a catalog revoke sends the reason and the code in the body and the header', async () => {
    await revokeCatalogVersion('openctem/sensor', '0.24.0', 'withdrawn', '654321')
    const { init, headers } = call()
    expect(JSON.parse(init.body as string)).toEqual({
      package_id: 'openctem/sensor',
      version: '0.24.0',
      reason: 'withdrawn',
      totp_code: '654321',
    })
    expect(headers[ADMIN_STEP_UP_HEADER]).toBe('654321')
  })

  it('a bundle import puts the reason and the code before the bundle', async () => {
    const bundle = new File(['x'], 'catalog.tar.gz')
    await importCatalogBundle(bundle, 'monthly update', '654321')
    const { init, headers } = call()
    const form = init.body as FormData
    expect([...form.keys()]).toEqual(['reason', 'totp_code', 'bundle'])
    expect(form.get('totp_code')).toBe('654321')
    expect(headers[ADMIN_STEP_UP_HEADER]).toBe('654321')
    expect(headers['X-CSRF-Token']).toBe('csrf-123')
  })
})
