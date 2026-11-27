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

import { useId, useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useRouter } from 'next/navigation'
import { Badge } from '@/components/ui/badge'
import { toast } from 'sonner'
import { AlertTriangle, Wifi } from 'lucide-react'
import { FormDialog, FormField, FormStack } from '@/features/shared/components/forms'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { invalidateScanRunsCache, useQuickScan } from '@/lib/api/scan-workflow-hooks'
import { refusedFromError, ScopeRefusalPanel, type ScopeRefusal } from '@/features/scope'
import { SelectionSummary, type ScanReadiness } from './target-picker/selection-summary'
import { ScannerSelect, useScannerOptions } from './scanner-select'

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
  /**
   * Preselect the first scanner with one of these capabilities ("Crawl this
   * site" picks a crawler); the person can still pick another.
   */
  preferCapabilities?: string[]
}

export function ScanAssetsDialog({
  open,
  onOpenChange,
  candidates,
  title,
  onSuccess,
  preferCapabilities,
}: ScanAssetsDialogProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const [picked, setScannerName] = useState('')
  // The same request ScannerSelect makes (one SWR key), read for the preference.
  const { options: scannerChoices } = useScannerOptions()
  const preferred = useMemo(
    () =>
      preferCapabilities?.length
        ? (scannerChoices.find((tool) =>
            tool.capabilities?.some((c) => preferCapabilities.includes(c))
          )?.name ?? '')
        : '',
    [scannerChoices, preferCapabilities]
  )
  const scannerName = picked || preferred
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [refused, setRefused] = useState<ScopeRefusal[]>([])
  const [readiness, setReadiness] = useState<ScanReadiness | null>(null)
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
  // Nothing the scope check lets through: starting would only be refused.
  const blocked = readiness?.state === 'blocked'
  const canSubmit = cappedTargets.length > 0 && !!scannerName && !isSubmitting && !blocked
  // Why Start is off, read with the button (a blocked scope check explains itself above).
  const reason =
    cappedTargets.length === 0
      ? t('scans.assetsDialog.noTargets')
      : !scannerName
        ? t('scans.err.scanner')
        : undefined
  const targetsLabelId = useId()

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
    <FormDialog
      open={open}
      onOpenChange={onOpenChange}
      title={title ?? t('scans.assetsDialog.title')}
      description={
        cappedTargets.length > 0
          ? cappedTargets.length === 1
            ? t('scans.assetsDialog.runOne')
            : t('scans.assetsDialog.runMany', undefined, { count: cappedTargets.length })
          : t('scans.assetsDialog.noAddress')
      }
      onSubmit={() => void handleSubmit()}
      submitting={isSubmitting}
      canSubmit={canSubmit}
      reason={reason}
      submitLabel={
        isSubmitting ? (
          t('scans.common.starting')
        ) : (
          <>
            <Wifi aria-hidden />
            {t('scans.quick.start')}
          </>
        )
      }
      data-testid="scan-assets-dialog"
    >
      <FormStack>
        {/* Target preview */}
        {cappedTargets.length > 0 && (
          <div
            role="group"
            aria-labelledby={targetsLabelId}
            className="flex min-w-0 flex-col gap-1.5"
          >
            <p id={targetsLabelId} className="text-dense font-medium">
              {t('scans.assetsDialog.targets')}
            </p>
            <div className="flex max-h-40 flex-wrap gap-2 overflow-y-auto rounded-md border p-3">
              {cappedTargets.slice(0, PREVIEW_LIMIT).map((target) => (
                <Badge // label-ok: a scan target (host name, address or range) is an identifier
                  key={target}
                  variant="secondary"
                  className="font-mono"
                >
                  {target}
                </Badge>
              ))}
              {cappedTargets.length > PREVIEW_LIMIT && (
                <Badge variant="outline">
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
          <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
            <span>
              {t('scans.assetsDialog.overCap', undefined, {
                count: targets.length,
                max: MAX_TARGETS,
              })}
            </span>
          </div>
        )}
        {isLargeSet && (
          <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
            <span>{t('scans.assetsDialog.large', undefined, { count: cappedTargets.length })}</span>
          </div>
        )}

        {/* Scanner: the tool registry's active scanners */}
        <FormField id="scan-assets-scanner" label={t('scans.basic.scanner')}>
          {(control) => (
            <ScannerSelect {...control} value={scannerName} onChange={setScannerName} />
          )}
        </FormField>

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
            onReadinessChange={setReadiness}
          />
        )}
      </FormStack>
    </FormDialog>
  )
}
