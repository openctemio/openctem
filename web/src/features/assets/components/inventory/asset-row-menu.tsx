'use client'

import { ExternalLink, MoreHorizontal, Pencil, Trash2 } from 'lucide-react'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import type { TypeView } from '@/features/asset-types/lib/type-view'
import { usePermissions } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'
import { rowActionsFor } from '../../lib/type-actions'
import type { Asset } from '../../types/asset.types'

interface AssetRowMenuProps {
  asset: Asset
  /** The list is one type: its own actions (a repository's Scan and Sync). */
  typeView: TypeView | null
  /** Trigger size: dense (28) in a table row, the default; `icon` on a phone card. */
  size?: 'icon-sm' | 'icon'
  /** Scanning sends work to the scanners at once, so the list asks first. */
  onScan: (asset: Asset) => void
  /** Open the edit form; absent without assets:write. */
  onEdit?: (asset: Asset) => void
  /** Ask to delete; absent without assets:delete. */
  onDelete?: (asset: Asset) => void
}

/**
 * An asset's action menu. The table row and the phone card render this one
 * component, so the two never offer different actions: the details page, the
 * asset's own actions (its link, copy, a repository's Scan and Sync), Edit,
 * then Delete. An action shows only with its permissions (the API checks
 * again); one that does not apply to this asset is dimmed with the reason.
 */
export function AssetRowMenu({
  asset,
  typeView,
  size = 'icon-sm',
  onScan,
  onEdit,
  onDelete,
}: AssetRowMenuProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const actions = rowActionsFor(asset, typeView, t).filter((a) =>
    a.permissions.every((p) => can(p))
  )
  const items: ActionMenuEntry[] = [
    {
      id: 'details',
      label: t('assets.inv.openDetails', 'Open details page'),
      icon: ExternalLink,
      href: assetDetailHref(asset.id),
    },
    ...actions.map((a) => ({
      id: a.id,
      label: a.label,
      icon: a.icon,
      onSelect: () => (a.id === 'scan' ? onScan(asset) : void a.run(asset)),
      disabledReason: a.unavailable?.(asset),
    })),
    ...(onEdit
      ? [
          {
            id: 'edit',
            label: t('assets.inv.edit', 'Edit'),
            icon: Pencil,
            onSelect: () => onEdit(asset),
          },
        ]
      : []),
    ...(onDelete
      ? [
          {
            id: 'delete',
            label: t('assets.inv.delete', 'Delete'),
            icon: Trash2,
            destructive: true,
            onSelect: () => onDelete(asset),
          },
        ]
      : []),
  ]
  const name = toDisplayText(asset.name, 80)
  const label = t('assets.inv.actionsFor', 'Actions for {name}', { name })
  return (
    <ActionMenu
      items={items}
      title={name}
      label={label}
      trigger={
        // Literal sizes: the icon-button guard reads them statically.
        size === 'icon' ? (
          <Button size="icon" variant="ghost" aria-label={label}>
            <MoreHorizontal className="h-4 w-4" aria-hidden />
          </Button>
        ) : (
          <Button size="icon-sm" variant="ghost" aria-label={label}>
            <MoreHorizontal className="h-4 w-4" aria-hidden />
          </Button>
        )
      }
    />
  )
}
