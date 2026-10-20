'use client'

/**
 * The one confirmation for deleting an asset, used by every page that
 * deletes one. Deletes go through features/assets/lib/safe-delete.
 *
 * Deleting cannot be undone from the console: the asset is detached from its
 * groups, owners, relationships and scope, so the user types its name.
 * An asset that has findings cannot be deleted (the API refuses it, 409
 * asset_has_findings). When the caller knows it has findings and offers
 * onArchive, the dialog offers Archive (reversible) instead of a delete that
 * would be refused.
 */

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

interface AssetDeleteDialogSharedProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  assetName?: string
  /** The asset's kind, already translated (e.g. t('...', 'repository')). */
  typeName: string
  onConfirm: () => unknown
  isSubmitting?: boolean
  /** The asset's finding count when the caller has it. */
  findingCount?: number
  /** Archives the asset; offered instead of the delete when it has findings. */
  onArchive?: () => unknown
}

export function AssetDeleteDialogShared({
  open,
  onOpenChange,
  assetName,
  typeName,
  onConfirm,
  isSubmitting,
  findingCount,
  onArchive,
}: AssetDeleteDialogSharedProps) {
  const { t } = useTranslation()
  const type = typeName.toLowerCase()
  const name = assetName ?? ''

  if (onArchive && findingCount && findingCount > 0) {
    return (
      <ConfirmDialog
        open={open}
        onOpenChange={onOpenChange}
        title={t('confirm.asset.archiveInsteadTitle', 'Archive the {type} "{name}"?', {
          type,
          name,
        })}
        desc={
          findingCount === 1
            ? t(
                'confirm.asset.archiveInsteadDescOne',
                'It has 1 finding, so it cannot be deleted: that would erase the finding history. Archiving hides it from lists and scans and keeps its findings; you can activate it again later.'
              )
            : t(
                'confirm.asset.archiveInsteadDesc',
                'It has {count} findings, so it cannot be deleted: that would erase the finding history. Archiving hides it from lists and scans and keeps its findings; you can activate it again later.',
                { count: findingCount }
              )
        }
        confirmText={
          isSubmitting ? t('confirm.archiving', 'Archiving…') : t('confirm.archive', 'Archive')
        }
        isLoading={isSubmitting}
        handleConfirm={onArchive}
      />
    )
  }

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={
        name
          ? t('confirm.asset.deleteTitle', 'Delete the {type} "{name}"?', { type, name })
          : t('confirm.asset.deleteTitleUnnamed', 'Delete this {type}?', { type })
      }
      desc={t(
        'confirm.asset.deleteDescIrreversible',
        'This cannot be undone. It leaves every list and is removed from its groups, owners, relationships and scope; its name can be used again. An asset that has findings is not deleted: archive it instead, so its finding history is kept.'
      )}
      confirmText={
        isSubmitting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
      }
      destructive
      isLoading={isSubmitting}
      typeToConfirm={name || undefined}
      handleConfirm={onConfirm}
    />
  )
}
