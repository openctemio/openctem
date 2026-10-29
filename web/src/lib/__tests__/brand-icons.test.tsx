// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { DEFAULT_BRAND, toBrand } from '@/lib/brand'

const state = vi.hoisted(() => ({ favicon: null as Response | null, brand: null as unknown }))
vi.mock('@/lib/brand-settings', () => ({
  brandFaviconResponse: async () => state.favicon,
  brandSettings: async () => state.brand,
}))
// The renderers must never read the session: any use of request headers or cookies fails the test.
vi.mock('next/headers', () => ({
  headers: () => {
    throw new Error('icon routes must not read request headers')
  },
  cookies: () => {
    throw new Error('icon routes must not read cookies')
  },
}))

import { brandIconResponse, brandOgResponse } from '@/lib/brand-icons'
import { APP_ICON_SVG, FAVICON_16_SVG, FAVICON_32_SVG } from '@/assets/brand-data.generated'
import manifest from '@/app/manifest'

/** Width and height from a PNG's IHDR chunk. */
async function pngSize(res: Response) {
  expect(res.headers.get('content-type')).toBe('image/png')
  const b = Buffer.from(await res.arrayBuffer())
  expect(b.subarray(1, 4).toString()).toBe('PNG')
  return [b.readUInt32BE(16), b.readUInt32BE(20)]
}

beforeEach(() => {
  state.favicon = null
  state.brand = DEFAULT_BRAND
})

describe('icon routes', () => {
  it('serve PNGs of the right size from the dedicated drawings', async () => {
    expect(await pngSize(await brandIconResponse(FAVICON_16_SVG, 16))).toEqual([16, 16])
    expect(await pngSize(await brandIconResponse(FAVICON_32_SVG, 32))).toEqual([32, 32])
    expect(await pngSize(await brandIconResponse(APP_ICON_SVG, 180))).toEqual([180, 180])
  })

  it('the operator favicon still wins over the built-in icon', async () => {
    state.favicon = new Response('operator-icon', { headers: { 'Content-Type': 'image/png' } })
    const res = await brandIconResponse(FAVICON_32_SVG, 32)
    expect(await res.text()).toBe('operator-icon')
  })
})

describe('social image', () => {
  it('is 1200 x 630, sets no cookie and reads no request data', async () => {
    const res = await brandOgResponse()
    expect(res.headers.get('set-cookie')).toBeNull()
    expect(await pngSize(res)).toEqual([1200, 630])
  })

  it('an operator brand gets its own card, not the OpenCTEM one', async () => {
    const own = Buffer.from(await (await brandOgResponse()).arrayBuffer())
    state.brand = toBrand({ name: 'Acme Exposure', short_name: 'Acme' })
    const res = await brandOgResponse()
    expect(await pngSize(res.clone())).toEqual([1200, 630])
    expect(Buffer.from(await res.arrayBuffer()).equals(own)).toBe(false)
  })
})

describe('web manifest', () => {
  it('uses the brand ink and our icons for OpenCTEM', async () => {
    const m = await manifest()
    expect(m.theme_color).toBe('#0A1628')
    expect(m.background_color).toBe('#0A1628')
    expect(m.name).toBe('OpenCTEM')
    expect(m.icons?.map((i) => i.src)).toEqual([
      '/brand/icon-192.png',
      '/brand/icon-512.png',
      '/brand/maskable-512.png',
    ])
  })

  it('an operator brand never advertises the OpenCTEM icons', async () => {
    state.brand = toBrand({ name: 'Acme Exposure', short_name: 'Acme' })
    const m = await manifest()
    expect(m.name).toBe('Acme Exposure')
    expect(JSON.stringify(m.icons)).not.toContain('/brand/')
  })
})
