'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useState, useEffect } from 'react'
import { Copy } from 'lucide-react'
import { toast } from 'sonner'

import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { FormDialog, FormField, FormSection, FormStack } from '@/features/shared/components/forms'
import { KeyValueList } from '@/features/shared/components/text-layout'

import { useCloneScanConfig, invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import { getErrorMessage } from '@/lib/api/error-handler'
import { notifyScannerConfigWarnings } from '../lib/scanner-config-warnings'
import type { ScanConfig } from '@/lib/api/scan-types'
import { configStatusName, scanTypeName, scheduleTypeName } from '../lib/labels'

interface CloneScanDialogProps {
  scan: ScanConfig | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: (newScan: ScanConfig) => void
}

export function CloneScanDialog({ scan, open, onOpenChange, onSuccess }: CloneScanDialogProps) {
  const { t } = useTranslation()
  const [newName, setNewName] = useState('')
  const { trigger: cloneScan, isMutating } = useCloneScanConfig(scan?.id ?? '')

  // Reset name when dialog opens with a new scan
  useEffect(() => {
    if (open && scan) {
      setNewName(t('scans.clone.copySuffix', undefined, { name: scan.name }))
    }
  }, [open, scan, t])

  const handleClone = async () => {
    if (!scan || !newName.trim()) return

    try {
      const result = await cloneScan({ name: newName.trim() })
      toast.success(t('scans.clone.created', undefined, { name: newName }))
      notifyScannerConfigWarnings(result, t)
      await invalidateScanConfigsCache()
      onOpenChange(false)
      if (onSuccess && result) {
        onSuccess(result)
      }
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.clone.failed')))
    }
  }

  const handleOpenChange = (newOpen: boolean) => {
    if (!newOpen) {
      setNewName('')
    }
    onOpenChange(newOpen)
  }

  if (!scan) return null

  const assetGroupCount = scan.asset_group_ids?.length || (scan.asset_group_id ? 1 : 0)
  const targetCount = scan.targets?.length || 0
  const targetParts = [
    assetGroupCount > 0 &&
      t(assetGroupCount > 1 ? 'scans.clone.groupMany' : 'scans.clone.groupOne', undefined, {
        count: assetGroupCount,
      }),
    targetCount > 0 &&
      t(targetCount > 1 ? 'scans.clone.directMany' : 'scans.clone.directOne', undefined, {
        count: targetCount,
      }),
  ].filter((part): part is string => !!part)
  const items = [
    { key: 'type', label: t('scans.clone.type'), value: scanTypeName(t, scan.scan_type) },
    {
      key: 'schedule',
      label: t('scans.clone.schedule'),
      value: scheduleTypeName(t, scan.schedule_type),
    },
    {
      key: 'targets',
      label: t('scans.clone.targets'),
      value:
        targetParts.length > 0 ? (
          targetParts.join(', ')
        ) : (
          <span className="text-muted-foreground">{t('scans.clone.noneConfigured')}</span>
        ),
    },
    {
      key: 'status',
      label: t('scans.clone.status'),
      value: (
        <>
          {configStatusName(t, scan.status)}{' '}
          <span className="text-muted-foreground">{t('scans.clone.asPaused')}</span>
        </>
      ),
    },
    ...(scan.tags && scan.tags.length > 0
      ? [
          {
            key: 'tags',
            label: t('scans.clone.tags'),
            value: (
              <span className="flex flex-wrap gap-1">
                {scan.tags.map((tag) => (
                  <Badge key={tag} variant="outline">
                    {tag}
                  </Badge>
                ))}
              </span>
            ),
          },
        ]
      : []),
  ]
  const named = newName.trim().length > 0

  return (
    <FormDialog
      open={open}
      onOpenChange={handleOpenChange}
      size="sm"
      title={t('scans.clone.title')}
      description={t('scans.clone.description', undefined, { name: scan.name })}
      onSubmit={() => void handleClone()}
      submitting={isMutating}
      canSubmit={named}
      reason={t('scans.clone.nameRequired')}
      submitLabel={
        isMutating ? (
          t('scans.clone.cloning')
        ) : (
          <>
            <Copy aria-hidden />
            {t('scans.clone.clone')}
          </>
        )
      }
      data-testid="clone-scan-dialog"
    >
      <FormStack>
        <FormField id="clone-name" label={t('scans.clone.newName')}>
          <Input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder={t('scans.clone.namePlaceholder')}
            autoFocus
          />
        </FormField>
        <FormSection title={t('scans.clone.toClone')}>
          <KeyValueList items={items} />
        </FormSection>
        <p className="text-cap text-muted-foreground">{t('scans.clone.note')}</p>
      </FormStack>
    </FormDialog>
  )
}
