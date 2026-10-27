import { brandOgResponse, OG_SIZE } from '@/lib/brand-icons'

/** Social preview image of every shared link. Renders the instance brand only. */
export const size = OG_SIZE
export const contentType = 'image/png'

export default async function OpenGraphImage() {
  return brandOgResponse()
}
