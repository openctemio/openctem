'use client'

/**
 * The actions of an asset's own page (`/assets/{id}`): one main action chosen
 * by the asset's state, every other one in the header's More menu.
 *
 *  - Scan now when the scan gate lets scans reach the asset now (the gate's
 *    own answer, `GET /assets/{id}/attribution`, which the page view already
 *    primes), the type has a scan target and the viewer holds scans:write and
 *    scans:execute; otherwise Edit (assets:write); otherwise none.
 *  - More: Edit (when it is not the main action), the lifecycle snooze
 *    (assets:write, as the API), Mark out of scope (scope:write or
 *    assets:write, while the answer still allows it), Archive (assets:write,
 *    with Undo), then the page's links.
 *
 * Every action opens the dialog the inventory and its drawer already use, with
 * the same gate and the same request; the API checks each one again.
 */

import { useMemo, useState, type ReactNode } from 'react'
import { Archive, Ban, Clock, Pencil, Play } from 'lucide-react'
import { type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { isScannableAssetType, useAssetTypeRegistry } from '@/features/asset-types'
import { useLifecycleSnooze } from '@/features/asset-lifecycle'
import { LazyScanAssetsDialog } from '@/features/scans/components/lazy-dialogs'
import { Permission, usePermissions } from '@/lib/permissions'
import { useAssetAttribution } from '../hooks/use-asset-attribution'
import type { Asset } from '../types/asset.types'
import { assetScanGates } from './asset-scanning-section'
import { useInventoryAssetForms } from './inventory/inventory-asset-forms'
import { MarkOutOfScopeAction, useArchiveAssets } from './inventory/mark-out-of-scope-action'

export interface AssetPageActions {
  /** The header's one main action, or nothing the viewer can do. */
  primary: ReactNode
  /** The actions for the header's More menu (before the page's links). */
  menu: ActionMenuEntry[]
  /** The dialogs those actions open. */
  dialogs: ReactNode
}

function snoozedNow(until: string | null | undefined): boolean {
  if (!until) return false
  const at = Date.parse(until)
  return Number.isFinite(at) && at > Date.now()
}

export function useAssetPageActions(asset: Asset, onChanged: () => void): AssetPageActions {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { registry } = useAssetTypeRegistry()
  // The scan gate's answer, only for a type scans can reach (the same rule as
  // the drawer's "Scope and scanning"): no request for any other type.
  const scannable = isScannableAssetType(registry, asset.type, asset.subType) !== false
  const { attribution, mutate: refreshAttribution } = useAssetAttribution(
    scannable ? asset.id : null
  )
  const { canScan, canExclude } = assetScanGates(asset, attribution, can)
  const canEdit = can(Permission.AssetsWrite)

  const forms = useInventoryAssetForms(registry, onChanged)
  const selected = useMemo(() => [asset], [asset])
  const archive = useArchiveAssets({ selected, onDone: onChanged })
  const snooze = useLifecycleSnooze({
    assetID: asset.id,
    isSnoozed: snoozedNow(asset.lifecyclePausedUntil),
    isStaleOrInactive: asset.status === 'stale' || asset.status === 'inactive',
    onUpdated: onChanged,
  })
  const [scanOpen, setScanOpen] = useState(false)
  const [outOpen, setOutOpen] = useState(false)

  const main: 'scan' | 'edit' | null = canScan ? 'scan' : canEdit ? 'edit' : null
  const primary =
    main === 'scan' ? (
      <Button onClick={() => setScanOpen(true)}>
        <Play aria-hidden />
        {t('assets.scanning.scanNow', 'Scan now')}
      </Button>
    ) : main === 'edit' ? (
      <Button onClick={() => forms.openEdit(asset)}>
        <Pencil aria-hidden />
        {t('assets.sheet.edit', 'Edit')}
      </Button>
    ) : null

  const menu: ActionMenuEntry[] = []
  if (canEdit && main !== 'edit') {
    menu.push({
      id: 'edit',
      label: t('assets.sheet.edit', 'Edit'),
      icon: Pencil,
      onSelect: () => forms.openEdit(asset),
    })
  }
  if (canEdit) {
    menu.push({
      kind: 'sub',
      id: 'snooze',
      label: snooze.heading,
      icon: Clock,
      items: [
        ...snooze.presets.map((p) => ({
          id: `snooze-${p.days}`,
          label: p.label,
          onSelect: () => void snooze.snooze(p.days),
          disabledReason: snooze.submitting
            ? t('assets.bulk.busy', 'Another change is running')
            : undefined,
        })),
        {
          id: 'snooze-custom',
          label: t('assets.snooze.custom', 'Custom…'),
          onSelect: snooze.openCustom,
        },
        ...(snooze.isSnoozed
          ? [
              {
                id: 'snooze-clear',
                section: 'clear',
                label: t('assets.snooze.clear', 'Clear snooze'),
                onSelect: () => void snooze.unsnooze(),
              },
            ]
          : []),
      ],
    })
  }
  if (canExclude) {
    menu.push({
      id: 'out-of-scope',
      label: t('assets.triage.action', 'Mark out of scope'),
      icon: Ban,
      onSelect: () => setOutOpen(true),
    })
  }
  if (archive.allowed && asset.status !== 'archived') {
    menu.push({
      id: 'archive',
      label: archive.label,
      icon: Archive,
      onSelect: () => void archive.run(),
      disabledReason:
        archive.disabledReason ??
        (archive.busy ? t('assets.bulk.busy', 'Another change is running') : undefined),
    })
  }

  const dialogs = (
    <>
      {forms.dialogs}
      {canEdit && snooze.dialog}
      {canExclude && (
        <MarkOutOfScopeAction
          selected={selected}
          open={outOpen}
          onOpenChange={setOutOpen}
          onDone={() => {
            void refreshAttribution()
            onChanged()
          }}
        />
      )}
      {canScan && (
        <LazyScanAssetsDialog
          open={scanOpen}
          onOpenChange={setScanOpen}
          candidates={[{ id: asset.id, label: asset.name, target: asset.name.trim() }]}
        />
      )}
    </>
  )

  return { primary, menu, dialogs }
}
