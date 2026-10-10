'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useState, useEffect } from 'react'
import { Loader2, Copy, Calendar, Target, Settings } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'

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

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Copy className="h-5 w-5" />
            {t('scans.clone.title')}
          </DialogTitle>
          <DialogDescription>
            {t('scans.clone.description', undefined, { name: scan.name })}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4 py-4">
            {/* New name input */}
            <div className="space-y-2">
              <Label htmlFor="clone-name">{t('scans.clone.newName')}</Label>
              <Input
                id="clone-name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder={t('scans.clone.namePlaceholder')}
                autoFocus
              />
            </div>

            {/* What will be cloned summary */}
            <div className="rounded-lg border bg-muted/30 p-4 space-y-3">
              <p className="text-sm font-medium">{t('scans.clone.toClone')}</p>

              <div className="grid gap-2 text-sm">
                {/* Scan Type */}
                <div className="flex items-center gap-2">
                  <Settings className="h-4 w-4 text-muted-foreground" />
                  <span className="text-muted-foreground">{t('scans.clone.type')}</span>
                  <Badge variant="outline">{scanTypeName(t, scan.scan_type)}</Badge>
                </div>

                {/* Schedule */}
                <div className="flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-muted-foreground" />
                  <span className="text-muted-foreground">{t('scans.clone.schedule')}</span>
                  <Badge variant="secondary">{scheduleTypeName(t, scan.schedule_type)}</Badge>
                </div>

                {/* Targets */}
                <div className="flex items-center gap-2">
                  <Target className="h-4 w-4 text-muted-foreground" />
                  <span className="text-muted-foreground">{t('scans.clone.targets')}</span>
                  <span>
                    {assetGroupCount > 0 && (
                      <Badge variant="secondary" className="me-1">
                        {t(
                          assetGroupCount > 1 ? 'scans.clone.groupMany' : 'scans.clone.groupOne',
                          undefined,
                          {
                            count: assetGroupCount,
                          }
                        )}
                      </Badge>
                    )}
                    {targetCount > 0 && (
                      <Badge variant="secondary">
                        {t(
                          targetCount > 1 ? 'scans.clone.directMany' : 'scans.clone.directOne',
                          undefined,
                          {
                            count: targetCount,
                          }
                        )}
                      </Badge>
                    )}
                    {assetGroupCount === 0 && targetCount === 0 && (
                      <span className="text-muted-foreground">
                        {t('scans.clone.noneConfigured')}
                      </span>
                    )}
                  </span>
                </div>

                {/* Status */}
                <div className="flex items-center gap-2">
                  <div
                    className={`h-2 w-2 rounded-full ${
                      scan.status === 'active'
                        ? 'bg-success'
                        : scan.status === 'paused'
                          ? 'bg-warning'
                          : 'bg-muted-foreground'
                    }`}
                  />
                  <span className="text-muted-foreground">{t('scans.clone.status')}</span>
                  <span>{configStatusName(t, scan.status)}</span>
                  <span className="text-xs text-muted-foreground">{t('scans.clone.asPaused')}</span>
                </div>
              </div>

              {/* Tags */}
              {scan.tags && scan.tags.length > 0 && (
                <div className="pt-2 border-t">
                  <span className="text-xs text-muted-foreground">{t('scans.clone.tags')} </span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {scan.tags.map((tag) => (
                      <Badge key={tag} variant="outline" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Note */}
            <p className="text-xs text-muted-foreground">{t('scans.clone.note')}</p>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)} disabled={isMutating}>
            {t('common.cancel')}
          </Button>
          <Button onClick={handleClone} disabled={!newName.trim() || isMutating}>
            {isMutating ? (
              <>
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
                {t('scans.clone.cloning')}
              </>
            ) : (
              <>
                <Copy className="me-2 h-4 w-4" />
                {t('scans.clone.clone')}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
