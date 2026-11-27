'use client'

/**
 * The scan page's header on the shared detail kit: what the scan is as
 * chips (state, type, intensity, or the platform policy that owns it), the
 * name, Run now as the main action, Edit and the schedule switch beside it,
 * and the rest (clone, copy, delete) in More. Gated as the API gates them:
 * a managed scan keeps only Clone and the copy entries.
 */

import { Copy, Hash, Link2, Pencil, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import type { ActionMenuEntry } from '@/components/ui/action-menu'
import { useTranslation } from '@/context/i18n-provider'
import { DetailPageHeader } from '@/features/shared/components/detail'
import { copyToClipboard } from '@/lib/clipboard'
import { shareableLink } from '@/lib/org-link'
import type { ScanConfig } from '@/lib/api/scan-types'
import { Permission, usePermissions } from '@/lib/permissions'
import { IntensityBadge } from '../intensity-badge'
import { scanStateLabel, useScanControls } from '../scan-controls'
import { isManagedScan, managedScanLabel, scanTypeLabel } from '../../lib/scan-status'

export function ScanPageHeader({
  config,
  onViewRun,
  onChanged,
  onEdit,
  onClone,
  onDelete,
}: {
  config: ScanConfig
  onViewRun: (runId: string) => void
  onChanged: () => void
  onEdit: () => void
  onClone: () => void
  onDelete: () => void
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const managed = isManagedScan(config)
  const controls = useScanControls(config, { onViewRun, onChanged })
  const canWrite = can(Permission.ScansWrite)

  const copy = async (text: string, done: string) => {
    const ok = await copyToClipboard(text)
    if (ok) toast.success(done)
    else toast.error(t('common.copyFailed', 'Could not copy'))
  }

  const menu: ActionMenuEntry[] = []
  if (canWrite) {
    menu.push({
      id: 'clone',
      label: managed ? t('scans.managed.clone') : t('scans.page.clone'),
      icon: Copy,
      onSelect: onClone,
    })
  }
  menu.push(
    {
      id: 'copy-link',
      label: t('scanDetail.header.copyLink', 'Copy link'),
      icon: Link2,
      onSelect: () =>
        void copy(
          shareableLink(`/scans/${config.id}`),
          t('scanDetail.header.linkCopied', 'Link copied')
        ),
    },
    {
      id: 'copy-id',
      label: t('scanDetail.header.copyId', 'Copy scan ID'),
      icon: Hash,
      onSelect: () => void copy(config.id, t('scanDetail.header.idCopied', 'Scan ID copied')),
    }
  )
  // DELETE /scans/{id} needs scans:delete; a policy's scan is not deleted here.
  if (!managed && can(Permission.ScansDelete)) {
    menu.push({
      id: 'delete',
      label: t('scanDetail.danger.action'),
      icon: Trash2,
      destructive: true,
      onSelect: onDelete,
    })
  }

  const type = scanTypeLabel(config, t).label

  return (
    <>
      <DetailPageHeader
        title={config.name}
        parent={{ href: '/scans', label: t('scanDetail.header.parent', 'Scans') }}
        chips={
          <ul
            className="flex min-w-0 flex-wrap items-center gap-1.5"
            aria-label={t('scanDetail.header.chips', 'About this scan')}
          >
            {managed ? (
              <>
                <li>
                  <Badge variant="secondary">{t('scans.managed.system')}</Badge>
                </li>
                <li className="min-w-0 text-meta break-words text-muted-foreground">
                  {managedScanLabel(config, t)}
                </li>
              </>
            ) : (
              <li>
                <Badge variant="outline">{scanStateLabel(config, t)}</Badge>
              </li>
            )}
            <li>
              <Badge variant="outline">{type}</Badge>
            </li>
            {config.intensity && (
              <li>
                <IntensityBadge intensity={config.intensity} />
              </li>
            )}
          </ul>
        }
        primary={controls.run ?? undefined}
        secondary={
          !managed && (canWrite || controls.schedule) ? (
            <>
              {canWrite && (
                <Button variant="outline" size="sm" onClick={onEdit}>
                  <Pencil className="me-1.5 h-4 w-4" aria-hidden />
                  {t('scans.page.edit')}
                </Button>
              )}
              {controls.schedule}
            </>
          ) : undefined
        }
        menu={menu}
      />
      {controls.dialogs}
    </>
  )
}
