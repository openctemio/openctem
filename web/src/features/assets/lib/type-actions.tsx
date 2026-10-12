/**
 * Row and bulk actions of an inventory row (research/77).
 *
 * Generic actions come from the registry data the row carries, never from
 * its type: "Open" for the first `url`-format attribute the asset holds
 * (repository web URL, API docs, store page, …), "Copy IPs" when it has
 * addresses. Type actions are the API operations only one type supports;
 * they live here, keyed by type, and nowhere else:
 *
 *  - repository: Scan (POST /assets/{id}/scan, assets:write + scans:execute)
 *    and Sync from the SCM (POST /assets/{id}/sync, assets:write).
 *
 * The API enforces the permissions; the menu only hides what the user cannot
 * do. Links go through `safeHref` (http/https only) and open with noopener.
 */
import type { LucideIcon } from 'lucide-react'
import { Copy, ExternalLink, Play, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { post } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { copyToClipboard } from '@/lib/clipboard'
import { safeHref } from '@/lib/safe-href'
import { Permission, type PermissionString } from '@/lib/permissions'
import { ASSET_PROPERTIES } from '@/features/asset-types/registry.generated'
import type { TypeView } from '@/features/asset-types/lib/type-view'
import type { Asset } from '../types'
import { attributeValue } from './attribute-value'
import { ipAddresses } from './service-facts'

export interface AssetAction {
  id: string
  label: string
  icon: LucideIcon
  /** Every one is needed. */
  permissions: PermissionString[]
  run: (asset: Asset) => Promise<void> | void
}

export interface BulkAssetAction {
  id: string
  label: string
  icon: LucideIcon
  permissions: PermissionString[]
  /** Runs on the selected assets this action applies to. */
  run: (assets: Asset[]) => Promise<void>
  applies: (asset: Asset) => boolean
}

/** The first safe http(s) link among the asset's `url`-format attributes. */
export function assetLink(asset: Asset, view: TypeView | null): string | undefined {
  const keys = view
    ? view.attributes.filter((a) => ASSET_PROPERTIES[a.key]?.format === 'url').map((a) => a.key)
    : []
  for (const key of keys) {
    const href = safeHref(attributeValue(asset, key), { allowRelative: false })
    if (href) return href
  }
  return safeHref(asset.repository?.webUrl, { allowRelative: false })
}

function canSync(asset: Asset): boolean {
  return !!asset.repository?.fullName && asset.provider !== 'local'
}

async function scanRepository(asset: Asset) {
  try {
    await post(`/api/v1/assets/${encodeURIComponent(asset.id)}/scan`, {})
    toast.success(`Scan started for ${asset.name}`)
  } catch (err) {
    toast.error(getErrorMessage(err, 'Failed to start the scan'))
  }
}

async function syncRepository(asset: Asset) {
  if (!canSync(asset)) {
    toast.warning(`${asset.name} was added by hand: connect a source-code integration to sync it`)
    return
  }
  try {
    await post(`/api/v1/assets/${encodeURIComponent(asset.id)}/sync`, {})
    toast.success(`${asset.name} synced`)
  } catch (err) {
    toast.error(getErrorMessage(err, 'Failed to sync'))
  }
}

/** Actions only one type supports, keyed by stored type. */
const TYPE_ACTIONS: Record<string, AssetAction[]> = {
  repository: [
    {
      id: 'scan',
      label: 'Scan',
      icon: Play,
      permissions: [Permission.AssetsWrite, Permission.ScansExecute],
      run: scanRepository,
    },
    {
      id: 'sync',
      label: 'Sync from source',
      icon: RefreshCw,
      permissions: [Permission.AssetsWrite],
      run: syncRepository,
    },
  ],
}

/** The bulk form of the type actions. */
const TYPE_BULK_ACTIONS: BulkAssetAction[] = [
  {
    id: 'scan',
    label: 'Scan',
    icon: Play,
    permissions: [Permission.AssetsWrite, Permission.ScansExecute],
    applies: (a) => a.type === 'repository',
    run: async (assets) => {
      const results = await Promise.allSettled(
        assets.map((a) => post(`/api/v1/assets/${encodeURIComponent(a.id)}/scan`, {}))
      )
      const failed = results.filter((r) => r.status === 'rejected').length
      if (failed > 0) toast.warning(`Started ${assets.length - failed} scans, ${failed} failed`)
      else toast.success(`Started ${assets.length} scans`)
    },
  },
  {
    id: 'sync',
    label: 'Sync from source',
    icon: RefreshCw,
    permissions: [Permission.AssetsWrite],
    applies: (a) => a.type === 'repository' && canSync(a),
    run: async (assets) => {
      const results = await Promise.allSettled(
        assets.map((a) => post(`/api/v1/assets/${encodeURIComponent(a.id)}/sync`, {}))
      )
      const failed = results.filter((r) => r.status === 'rejected').length
      if (failed > 0) toast.warning(`Synced ${assets.length - failed}, ${failed} failed`)
      else toast.success(`Synced ${assets.length}`)
    },
  },
]

/** The row menu's actions for an asset (before Edit and Delete). */
export function rowActionsFor(asset: Asset, view: TypeView | null): AssetAction[] {
  const out: AssetAction[] = []
  const link = assetLink(asset, view)
  if (link) {
    out.push({
      id: 'open',
      label: 'Open link',
      icon: ExternalLink,
      permissions: [],
      run: () => {
        window.open(link, '_blank', 'noopener,noreferrer')
      },
    })
  }
  const ips = ipAddresses(asset)
  if (ips.length > 0) {
    out.push({
      id: 'copy-ips',
      label: ips.length === 1 ? 'Copy IP' : 'Copy IPs',
      icon: Copy,
      permissions: [],
      run: async () => {
        if (await copyToClipboard(ips.join(', '))) toast.success('Copied')
      },
    })
  }
  out.push({
    id: 'copy-name',
    label: 'Copy name',
    icon: Copy,
    permissions: [],
    run: async () => {
      if (await copyToClipboard(asset.name)) toast.success('Copied')
    },
  })
  return [...out, ...(TYPE_ACTIONS[asset.type] ?? [])]
}

/** The bulk actions that apply to at least one selected asset. */
export function bulkActionsFor(selected: Asset[]): BulkAssetAction[] {
  return TYPE_BULK_ACTIONS.filter((a) => selected.some(a.applies))
}
