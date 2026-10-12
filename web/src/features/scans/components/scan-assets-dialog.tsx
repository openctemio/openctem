/**
 * Scan Assets Dialog
 *
 * Confirmation dialog for the attack-surface "scan these assets now" flow.
 * Given a set of assets (already resolved to scan targets by the caller),
 * it shows the resolved target count, warns about skipped / large / capped
 * sets, offers a scanner picker, and triggers POST /api/v1/scans/quick.
 *
 * Distinct from {@link ./quick-scan-dialog QuickScanDialog}, which takes
 * free-text targets. This one is driven by a list of assets.
 */

'use client'

import { useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useRouter } from 'next/navigation'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { toast } from 'sonner'
import { AlertTriangle, Loader2, Wifi } from 'lucide-react'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { invalidateScanRunsCache, useQuickScan } from '@/lib/api/scan-workflow-hooks'
import { refusedFromError, ScopeRefusalPanel, type ScopeRefusal } from '@/features/scope'
import { SelectionSummary } from './target-picker/selection-summary'
import { ScannerSelect } from './scanner-select'

/** Backend hard cap on targets per quick scan (see POST /scans/quick, 1..1000). */
const MAX_TARGETS = 1000
/** Above this many targets we treat the run as "large" and warn explicitly. */
const LARGE_SET_THRESHOLD = 100
/** How many targets to preview in the dialog before truncating. */
const PREVIEW_LIMIT = 8

/**
 * An asset the caller wants to scan. `target` is the address the scanner
 * will hit (IP / hostname / domain / URL); empty string means the asset
 * has no usable target and will be skipped.
 */
export interface ScanCandidate {
  id: string
  label: string
  target: string
}

interface ScanAssetsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The candidate assets to scan (may include unresolvable ones). */
  candidates: ScanCandidate[]
  /** Optional custom heading, e.g. "Scan Network". */
  title?: string
  /** Called after a scan is successfully triggered. */
  onSuccess?: () => void
}

export function ScanAssetsDialog({
  open,
  onOpenChange,
  candidates,
  title,
  onSuccess,
}: ScanAssetsDialogProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const [scannerName, setScannerName] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [refused, setRefused] = useState<ScopeRefusal[]>([])
  const { trigger: quickScan } = useQuickScan()

  // Resolve + de-duplicate targets; track how many were unusable.
  const { targets, skippedCount } = useMemo(() => {
    const seen = new Set<string>()
    const resolved: string[] = []
    let skipped = 0
    for (const c of candidates) {
      const target = c.target?.trim()
      if (!target) {
        skipped += 1
        continue
      }
      if (seen.has(target)) continue
      seen.add(target)
      resolved.push(target)
    }
    return { targets: resolved, skippedCount: skipped }
  }, [candidates])

  const isOverCap = targets.length > MAX_TARGETS
  const cappedTargets = useMemo(() => targets.slice(0, MAX_TARGETS), [targets])
  const isLargeSet = cappedTargets.length > LARGE_SET_THRESHOLD
  const canSubmit = cappedTargets.length > 0 && !!scannerName && !isSubmitting

  const handleSubmit = async () => {
    if (cappedTargets.length === 0) {
      toast.error(t('scans.assetsDialog.noTargets'))
      return
    }

    setIsSubmitting(true)
    setRefused([])
    try {
      await quickScan({
        targets: cappedTargets,
        scanner_name: scannerName || undefined,
      })

      await invalidateScanRunsCache()
      toast.success(
        cappedTargets.length === 1
          ? t('scans.assetsDialog.startedOne')
          : t('scans.assetsDialog.startedMany', undefined, { count: cappedTargets.length }),
        {
          action: {
            label: t('scans.assetsDialog.viewRun'),
            onClick: () => router.push('/scans/runs'),
          },
        }
      )
      onSuccess?.()
      onOpenChange(false)
    } catch (error) {
      const scopeRefused = refusedFromError(error)
      if (scopeRefused.length > 0) {
        setRefused(scopeRefused)
        return
      }
      if (error instanceof ApiClientError && error.statusCode === 429) {
        toast.error(t('scans.assetsDialog.rateLimit'))
      } else if (error instanceof ApiClientError && error.statusCode === 400) {
        toast.error(getErrorMessage(error, t('scans.assetsDialog.rejected')))
      } else {
        toast.error(getErrorMessage(error, t('scans.assetsDialog.startFailed')))
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !isSubmitting && onOpenChange(o)}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{title ?? t('scans.assetsDialog.title')}</DialogTitle>
          <DialogDescription>
            {cappedTargets.length > 0
              ? cappedTargets.length === 1
                ? t('scans.assetsDialog.runOne')
                : t('scans.assetsDialog.runMany', undefined, { count: cappedTargets.length })
              : t('scans.assetsDialog.noAddress')}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-4">
          {/* Target preview */}
          {cappedTargets.length > 0 && (
            <div className="space-y-2">
              <Label>{t('scans.assetsDialog.targets')}</Label>
              <div className="flex flex-wrap gap-2 rounded-md border p-3 max-h-40 overflow-y-auto">
                {cappedTargets.slice(0, PREVIEW_LIMIT).map((target) => (
                  <Badge key={target} variant="secondary" className="font-mono text-xs">
                    {target}
                  </Badge>
                ))}
                {cappedTargets.length > PREVIEW_LIMIT && (
                  <Badge variant="outline" className="text-xs">
                    {t('scans.assetsDialog.more', undefined, {
                      count: cappedTargets.length - PREVIEW_LIMIT,
                    })}
                  </Badge>
                )}
              </div>
            </div>
          )}

          {/* Guards / warnings */}
          {skippedCount > 0 && (
            <p className="text-xs text-muted-foreground">
              {t(
                skippedCount === 1
                  ? 'scans.assetsDialog.skippedOne'
                  : 'scans.assetsDialog.skippedMany',
                undefined,
                { count: skippedCount }
              )}
            </p>
          )}
          {isOverCap && (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                {t('scans.assetsDialog.overCap', undefined, {
                  count: targets.length,
                  max: MAX_TARGETS,
                })}
              </span>
            </div>
          )}
          {isLargeSet && (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-400">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                {t('scans.assetsDialog.large', undefined, { count: cappedTargets.length })}
              </span>
            </div>
          )}

          {/* Scanner: the tool registry's active scanners (it was a fixed list) */}
          <div className="space-y-2">
            <Label htmlFor="scan-assets-scanner">{t('scans.basic.scanner')}</Label>
            <ScannerSelect id="scan-assets-scanner" value={scannerName} onChange={setScannerName} />
          </div>

          {refused.length > 0 ? (
            <ScopeRefusalPanel refused={refused} />
          ) : (
            // The same live scope check as New Scan and Quick scan.
            <SelectionSummary
              targets={cappedTargets}
              chips={cappedTargets.map((target) => ({
                key: target,
                label: target,
                kind: 'typed' as const,
              }))}
              groupCount={0}
              invalidCount={0}
              scannerName={scannerName}
            />
          )}
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit}>
            {isSubmitting ? (
              <>
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
                {t('scans.common.starting')}
              </>
            ) : (
              <>
                <Wifi className="me-2 h-4 w-4" />
                {t('scans.quick.start')}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
