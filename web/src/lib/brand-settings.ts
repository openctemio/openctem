import { env } from '@/lib/env'
import { DEFAULT_BRAND, toBrand, type Brand, type BrandResponse } from '@/lib/brand'
import { resolveHelpLinks, type HelpSettingsResponse } from '@/lib/help-links'

/**
 * Fetches the instance brand from the API's public GET /api/v1/brand, on the
 * server, with a short cache. Any failure (API down, older API without the
 * endpoint, a malformed answer) gives the OpenCTEM defaults; every value is
 * checked again by toBrand before it reaches a page.
 */
export async function brandSettings(): Promise<Brand> {
  const [brand, help] = await Promise.all([instanceBrand(), helpSettings()])
  return { ...brand, help: resolveHelpLinks(help) }
}

async function instanceBrand(): Promise<Brand> {
  try {
    const res = await fetch(`${env.api.url}/api/v1/brand`, {
      headers: { Accept: 'application/json' },
      next: { revalidate: 60 },
      signal: AbortSignal.timeout(3000),
    })
    if (!res.ok) return DEFAULT_BRAND
    return toBrand((await res.json()) as BrandResponse)
  } catch {
    return DEFAULT_BRAND
  }
}

/** The operator's help links and security contact (public GET /api/v1/legal); null on any failure. */
async function helpSettings(): Promise<HelpSettingsResponse | null> {
  try {
    const res = await fetch(`${env.api.url}/api/v1/legal`, {
      headers: { Accept: 'application/json' },
      next: { revalidate: 60 },
      signal: AbortSignal.timeout(3000),
    })
    return res.ok ? ((await res.json()) as HelpSettingsResponse) : null
  } catch {
    return null
  }
}

/**
 * The brand's favicon as a response for the icon routes, or null when the
 * built-in icon applies (no favicon set, or the API cannot serve it). The
 * path was validated by toBrand (a same-origin /api/v1/brand/images/ path),
 * so the fetch only ever reaches the API.
 */
export async function brandFaviconResponse(): Promise<Response | null> {
  const brand = await brandSettings()
  if (!brand.faviconUrl) return null
  try {
    const res = await fetch(`${env.api.url}${brand.faviconUrl}`, {
      next: { revalidate: 60 },
      signal: AbortSignal.timeout(3000),
    })
    const type = res.headers.get('content-type') ?? ''
    if (!res.ok || !type.startsWith('image/')) return null
    return new Response(await res.arrayBuffer(), {
      headers: {
        'Content-Type': type,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'public, max-age=300',
      },
    })
  } catch {
    return null
  }
}
