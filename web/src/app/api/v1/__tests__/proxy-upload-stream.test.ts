/**
 * @vitest-environment node
 *
 * Import uploads are streamed to the API up to the route's own limit, never
 * read into the proxy's memory; every other body keeps the 12 MiB cap.
 * Before, every upload above 12 MiB was refused here although the finding
 * import accepts 110 MiB.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cookies } from 'next/headers'
import { NextRequest } from 'next/server'

import { POST as v1POST } from '@/app/api/v1/[...path]/route'

const APP = 'https://app.example.test'
const MiB = 1024 * 1024
const CSRF = 'csrf-pair'
const TENANT = '01a12aa1-8071-74f1-999a-9de298f5b787'

function jwt(expInSeconds: number): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'HS256' })}.${b64({ exp: Math.floor(Date.now() / 1000) + expInSeconds })}.sig`
}

function bodyOf(size: number, chunk = MiB): ReadableStream<Uint8Array> {
  let sent = 0
  return new ReadableStream({
    pull(c) {
      if (sent >= size) {
        c.close()
        return
      }
      const n = Math.min(chunk, size - sent)
      sent += n
      c.enqueue(new Uint8Array(n))
    },
  })
}

function post(
  path: string,
  body: ReadableStream<Uint8Array>,
  headers: Record<string, string> = {}
) {
  const req = new NextRequest(`${APP}/api/v1/${path}`, {
    method: 'POST',
    body,
    headers: {
      origin: APP,
      'x-csrf-token': CSRF,
      cookie: `csrf_token=${CSRF}`,
      'content-type': 'multipart/form-data; boundary=x',
      ...headers,
    },
    duplex: 'half',
  } as ConstructorParameters<typeof NextRequest>[1])
  return v1POST(req, { params: Promise.resolve({ path: path.split('/') }) })
}

describe('API proxy upload bodies', () => {
  const fetchMock = vi.fn()
  let token = jwt(600)

  beforeEach(() => {
    token = jwt(600)
    vi.mocked(cookies).mockImplementation(
      async () =>
        ({
          get: (name: string) => {
            const values: Record<string, string> = {
              auth_token: token,
              refresh_token: 'rt',
              csrf_token: CSRF,
              app_tenant: JSON.stringify({ id: TENANT, slug: 't', role: 'member' }),
            }
            return name in values ? { name, value: values[name] } : undefined
          },
          set: vi.fn(),
          delete: vi.fn(),
        }) as unknown as Awaited<ReturnType<typeof cookies>>
    )
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/api/v1/auth/refresh')) {
        return new Response(
          JSON.stringify({ access_token: jwt(900), refresh_token: 'rt2', expires_in: 900 }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
      }
      let size = 0
      const b = init?.body
      if (b instanceof ReadableStream) {
        const reader = b.getReader()
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          size += value.byteLength
        }
      } else if (b instanceof Uint8Array) {
        size = b.byteLength
      }
      return new Response(JSON.stringify({ size, streamed: b instanceof ReadableStream }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('streams a 20 MiB finding import to the API', async () => {
    const res = await post('findings/imports', bodyOf(20 * MiB), {
      'content-length': String(20 * MiB),
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ size: 20 * MiB, streamed: true })
    const init = fetchMock.mock.calls.at(-1)?.[1] as RequestInit & { duplex?: string }
    expect(init.duplex).toBe('half')
  })

  it('refuses an import whose Content-Length is over the route limit before forwarding', async () => {
    const res = await post('findings/imports', bodyOf(1), {
      'content-length': String(110 * MiB + 1),
    })
    expect(res.status).toBe(413)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('cuts a streamed import that passes the limit without an honest Content-Length', async () => {
    const res = await post('assets/import/csv', bodyOf(50 * MiB + 2 * MiB))
    expect(res.status).toBe(413)
  })

  it('keeps the 12 MiB cap on other routes', async () => {
    const res = await post('attachments', bodyOf(1), { 'content-length': String(13 * MiB) })
    expect(res.status).toBe(413)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('refreshes a token about to expire before streaming, since a 401 cannot be replayed', async () => {
    token = jwt(10)
    const res = await post('findings/imports', bodyOf(MiB))
    expect(res.status).toBe(200)
    const urls = fetchMock.mock.calls.map(([u]) => String(u))
    expect(urls[0]).toMatch(/\/api\/v1\/auth\/refresh$/)
    expect(urls).toHaveLength(2)
  })
})
