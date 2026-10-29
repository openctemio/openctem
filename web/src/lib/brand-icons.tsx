import { ImageResponse } from 'next/og'
import { brandFaviconResponse, brandSettings } from '@/lib/brand-settings'
import { BRAND_INK, UPSTREAM_NAME } from '@/lib/brand'
import { OG_IMAGE_SVG } from '@/assets/brand-data.generated'

/**
 * Shared renderers of the icon routes (favicon, apple icon, social image) of
 * the tenant app and the platform console. The drawings come from the brand
 * SVGs (src/assets/brand, through brand-gen), never from copied geometry.
 *
 * None of these read the session, a cookie or a request header: they render
 * the instance brand only, so their output is the same for everyone and safe
 * to cache.
 */

const dataUri = (svg: string) => `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`

/**
 * A square icon: the operator's own favicon when the instance brand has one,
 * otherwise the given drawing (an SVG with its own tile) at `px` x `px`.
 */
export async function brandIconResponse(svg: string, px: number): Promise<Response> {
  const branded = await brandFaviconResponse()
  if (branded) return branded
  return new ImageResponse(
    <div style={{ display: 'flex', width: '100%', height: '100%' }}>
      {/* eslint-disable-next-line @next/next/no-img-element -- rendered to a PNG, not shown in a page */}
      <img src={dataUri(svg)} width={px} height={px} alt="" />
    </div>,
    { width: px, height: px }
  )
}

export const OG_SIZE = { width: 1200, height: 630 }

/** The 1200 x 630 social image: our lockup card, or the operator brand's name on ink. */
export async function brandOgResponse(): Promise<Response> {
  const brand = await brandSettings()
  if (brand.name === UPSTREAM_NAME) {
    return new ImageResponse(
      <div style={{ display: 'flex', width: '100%', height: '100%' }}>
        {/* eslint-disable-next-line @next/next/no-img-element -- rendered to a PNG, not shown in a page */}
        <img src={dataUri(OG_IMAGE_SVG)} {...OG_SIZE} alt="" />
      </div>,
      OG_SIZE
    )
  }
  return new ImageResponse(
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '100%',
        height: '100%',
        background: BRAND_INK,
        color: '#FAFAF9', // label-ok: the brand paper on the ink of a rendered social image, outside the theme
        fontSize: 96,
        fontWeight: 600,
      }}
    >
      {brand.name}
    </div>,
    OG_SIZE
  )
}
