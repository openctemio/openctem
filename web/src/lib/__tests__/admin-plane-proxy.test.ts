import { describe, it, expect, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { proxy } from '@/proxy'

const SITE = 'https://openctem.example'

function get(path: string, plane?: string) {
  const headers: Record<string, string> = {}
  if (plane) headers['x-openctem-plane'] = plane
  return proxy(new NextRequest(`${SITE}${path}`, { headers }))
}

describe('proxy.ts: the console on its own origin', () => {
  afterEach(() => vi.unstubAllEnvs())

  it('the console site serves only the console', () => {
    vi.stubEnv('OPENCTEM_ADMIN_PLANE', 'separate')
    expect(get('/findings', 'admin').status).toBe(404)
    expect(get('/api/v1/findings', 'admin').status).toBe(404)
    expect(get('/admin/organizations', 'admin').status).not.toBe(404)
    expect(get('/api/v1/admin/auth/validate', 'admin').status).not.toBe(404)
    const root = get('/', 'admin')
    expect(root.status).toBe(307)
    expect(new URL(root.headers.get('location') ?? '').pathname).toBe('/admin')
  })

  it('the main site has no console', () => {
    vi.stubEnv('OPENCTEM_ADMIN_PLANE', 'separate')
    expect(get('/admin').status).toBe(404)
    expect(get('/admin/login').status).toBe(404)
    expect(get('/api/v1/admin/tenants').status).toBe(404)
    expect(get('/login').status).not.toBe(404)
  })

  it('changes nothing while the console shares the origin', () => {
    vi.stubEnv('OPENCTEM_ADMIN_PLANE', '')
    expect(get('/admin/login').status).not.toBe(404)
    expect(get('/api/v1/admin/tenants').status).not.toBe(404)
  })
})
