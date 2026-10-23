/**
 * @vitest-environment node
 */
import { describe, expect, it } from 'vitest'

import {
  accessTokenExpiresSoon,
  DEFAULT_PROXY_BODY_LIMIT,
  limitBodyStream,
  ProxyBodyTooLargeError,
  proxyBodyPolicy,
} from '@/lib/api/proxy-upload'

const MiB = 1024 * 1024
const CAMPAIGN = '0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'

function streamOf(...chunks: number[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(c) {
      for (const n of chunks) c.enqueue(new Uint8Array(n))
      c.close()
    },
  })
}

async function drain(s: ReadableStream<Uint8Array>): Promise<number> {
  const reader = s.getReader()
  let n = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return n
    n += value.byteLength
  }
}

function jwt(payload: object): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'HS256' })}.${b64(payload)}.sig`
}

describe('proxyBodyPolicy', () => {
  it('streams the import routes up to the API limit of each', () => {
    expect(proxyBodyPolicy('POST', 'findings/imports')).toEqual({ limit: 110 * MiB, stream: true })
    expect(proxyBodyPolicy('post', 'findings/imports/')).toEqual({ limit: 110 * MiB, stream: true })
    expect(proxyBodyPolicy('POST', 'components/import')).toEqual({
      limit: 50 * MiB + 1,
      stream: true,
    })
    expect(proxyBodyPolicy('POST', 'assets/import/csv')).toEqual({ limit: 50 * MiB, stream: true })
    expect(proxyBodyPolicy('POST', `pentest/campaigns/${CAMPAIGN}/findings/import`)).toEqual({
      limit: 51 * MiB,
      stream: true,
    })
  })

  it('keeps every other request at the default, read into memory', () => {
    const def = { limit: DEFAULT_PROXY_BODY_LIMIT, stream: false }
    expect(proxyBodyPolicy('POST', 'attachments')).toEqual(def)
    expect(proxyBodyPolicy('PUT', 'findings/imports')).toEqual(def)
    // The old singular route is gone: it gets the default limit.
    expect(proxyBodyPolicy('POST', 'findings/import')).toEqual(def)
    expect(proxyBodyPolicy('POST', 'findings/import/x')).toEqual(def)
    expect(proxyBodyPolicy('POST', 'x/findings/import')).toEqual(def)
    expect(proxyBodyPolicy('POST', 'pentest/campaigns/not-a-uuid/findings/import')).toEqual(def)
  })
})

describe('limitBodyStream', () => {
  it('passes a body at the limit through', async () => {
    expect(await drain(limitBodyStream(streamOf(4, 4, 2), 10))).toBe(10)
  })

  it('errors once the body passes the limit', async () => {
    await expect(drain(limitBodyStream(streamOf(4, 4, 3), 10))).rejects.toBeInstanceOf(
      ProxyBodyTooLargeError
    )
  })
})

describe('accessTokenExpiresSoon', () => {
  const now = Date.UTC(2026, 9, 12, 12, 0, 0)
  it('is false for a token valid well beyond the skew', () => {
    expect(accessTokenExpiresSoon(jwt({ exp: now / 1000 + 600 }), 60, now)).toBe(false)
  })
  it('is true for a token expiring within the skew or expired', () => {
    expect(accessTokenExpiresSoon(jwt({ exp: now / 1000 + 30 }), 60, now)).toBe(true)
    expect(accessTokenExpiresSoon(jwt({ exp: now / 1000 - 1 }), 60, now)).toBe(true)
  })
  it('is true for a token it cannot read', () => {
    expect(accessTokenExpiresSoon('opaque', 60, now)).toBe(true)
    expect(accessTokenExpiresSoon(jwt({}), 60, now)).toBe(true)
    expect(accessTokenExpiresSoon('a.###.c', 60, now)).toBe(true)
  })
})
