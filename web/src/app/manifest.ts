import type { MetadataRoute } from 'next'
import { brandSettings } from '@/lib/brand-settings'
import { BRAND_INK, UPSTREAM_NAME } from '@/lib/brand'

/**
 * Web app manifest of the instance brand: its name and colour, our icons when
 * the brand is OpenCTEM and the operator's own favicon otherwise (a
 * same-origin path validated by toBrand).
 */
export default async function manifest(): Promise<MetadataRoute.Manifest> {
  const brand = await brandSettings()
  const own = brand.name === UPSTREAM_NAME && !brand.faviconUrl
  return {
    name: brand.name,
    short_name: brand.shortName,
    start_url: '/',
    display: 'standalone',
    theme_color: BRAND_INK,
    background_color: BRAND_INK,
    icons: own
      ? [
          { src: '/brand/icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: '/brand/icon-512.png', sizes: '512x512', type: 'image/png' },
          {
            src: '/brand/maskable-512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'maskable',
          },
        ]
      : brand.faviconUrl
        ? [{ src: brand.faviconUrl, sizes: 'any' }]
        : [],
  }
}
