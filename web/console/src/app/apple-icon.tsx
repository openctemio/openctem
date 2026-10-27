import { brandIconResponse } from '@/lib/brand-icons'
import { APP_ICON_SVG } from '@/assets/brand-data.generated'

/** Apple touch icon (iOS "Add to Home Screen"): the master symbol on the ink tile. */
export const size = { width: 180, height: 180 }
export const contentType = 'image/png'

export default async function AppleIcon() {
  return brandIconResponse(APP_ICON_SVG, size.width)
}
