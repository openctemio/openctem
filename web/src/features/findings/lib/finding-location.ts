/**
 * Where a finding is, split into the asset and the place on that asset.
 *
 * The list used to show one string: the file path or URL when there was one,
 * else the asset name, cut at the end. Two findings of the same check on one
 * web application then looked identical ("https://shop.example.com/api/v2…"),
 * because the part that differs is the end of the URL. Splitting the asset
 * from the detail lets the list show the asset once and the detail relative
 * to it (a URL on the asset's own host becomes its path), and the cell keeps
 * the tail of the detail visible.
 *
 * Every value here is scanner-supplied text: callers render it as React text
 * (TruncatedText), never as markup or a link.
 */

export interface FindingLocationInput {
  asset_id?: string
  asset?: { name?: string } | null
  file_path?: string
  start_line?: number
  first_detected_branch?: string
  network_port?: number
  network_transport?: string
  metadata?: Record<string, unknown> | null
}

export interface FindingLocation {
  /** The asset's name; empty when the finding has none. */
  asset: string
  /** The place on the asset (path, URL path, file:line, port); empty when the asset is the whole location. */
  detail: string
  /** Asset and detail together, for a tooltip, a copy or a search. */
  full: string
}

function parseHttpUrl(value: string): URL | null {
  if (!/^https?:\/\//i.test(value)) return null
  try {
    return new URL(value)
  } catch {
    return null
  }
}

/** The host an asset name stands for: a URL's host, else the name itself. */
function assetHost(name: string): string {
  const url = parseHttpUrl(name)
  return (url ? url.host : name).toLowerCase()
}

export function findingLocation(f: FindingLocationInput): FindingLocation {
  const asset = f.asset?.name?.trim() ?? ''
  let detail = ''

  const path = f.file_path?.trim() ?? ''
  if (path) {
    const url = parseHttpUrl(path)
    if (url && asset && url.host.toLowerCase() === assetHost(asset)) {
      // Same host as the asset: the path and query are what differ.
      detail = `${url.pathname}${url.search}${url.hash}` || '/'
    } else {
      detail = path
      if (!url && f.start_line) detail = `${detail}:${f.start_line}`
      if (!url && f.first_detected_branch) detail = `${f.first_detected_branch}:${detail}`
    }
  } else if (f.network_port) {
    detail = `:${f.network_port}${f.network_transport ? `/${f.network_transport}` : ''}`
  }

  if (!asset && !detail) {
    const targets = f.metadata?.affected_assets
    if (Array.isArray(targets) && targets.length > 0) {
      const first = String(targets[0])
      detail = targets.length > 1 ? `${first} +${targets.length - 1}` : first
    }
  }

  // A detail equal to the asset name adds nothing.
  if (detail && detail === asset) detail = ''

  const full =
    asset && detail
      ? detail.startsWith('/') || detail.startsWith(':')
        ? `${asset}${detail}`
        : `${asset}, ${detail}`
      : asset || detail
  return { asset, detail, full }
}
