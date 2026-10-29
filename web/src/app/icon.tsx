import { brandIconResponse } from '@/lib/brand-icons'
import { FAVICON_16_SVG, FAVICON_32_SVG } from '@/assets/brand-data.generated'

/**
 * Favicon: the dedicated 16 px and 32 px drawings (whole-pixel brackets and
 * marker), so the mark stays sharp in a browser tab. The operator brand's own
 * favicon wins when one is configured.
 */
const SIZES = [16, 32] as const

export function generateImageMetadata() {
  return SIZES.map((px) => ({
    id: String(px),
    size: { width: px, height: px },
    contentType: 'image/png',
  }))
}

export default async function Icon({ id }: { id: Promise<string | number> }) {
  const px = Number(await id) === 16 ? 16 : 32
  return brandIconResponse(px === 16 ? FAVICON_16_SVG : FAVICON_32_SVG, px)
}
