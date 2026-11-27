/**
 * Quick Scan Dialog
 *
 * Run a scanner on typed targets right away, without creating a scan
 * configuration (owner decision D10). The API keeps the run's scan unsaved
 * (ad hoc): it stays out of the Configurations list and creates no asset
 * group. Once the scan has started, "Save as scan" turns it into a
 * configuration under a name the user picks.
 */

'use client'

import { useState, useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { FormDialog, FormField, FormStack } from '@/features/shared/components/forms'
import { toast } from 'sonner'
import { CheckCircle2, Loader2, Save, Zap } from 'lucide-react'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  invalidateScanRunsCache,
  invalidateScanManagementStatsCache,
  useQuickScan,
} from '@/lib/api/scan-workflow-hooks'
import type { QuickScanResponse } from '@/lib/api/scan-workflow-types'
import { invalidateScanConfigsCache, useSaveQuickScan } from '@/lib/api/scan-hooks'
import { ScannerSelect } from './scanner-select'
import { PasteSource } from './target-picker/paste-source'
import { SelectionSummary, type ScanReadiness } from './target-picker/selection-summary'
import { QuickScanPreviewPanel } from './quick-scan-preview'
import { parsePastedTargets } from '../lib/target-format'
import { enTranslate, type Translate } from '../lib/translate'
import { refusedFromError, ScopeRefusalPanel, type ScopeRefusal } from '@/features/scope'

interface QuickScanDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

/** Parse targets from text, supporting newline, comma, and semicolon separators. */
export function parseTargets(text: string): string[] {
  return text
    .split(/[\n,;]+/)
    .map((t) => t.trim())
    .filter(Boolean)
}

/** Default name offered by "Save as scan". */
export function defaultSaveName(
  scanner: string,
  targets: string[],
  t: Translate = enTranslate
): string {
  if (targets.length === 0) return t('scans.quick.defaultName', undefined, { scanner })
  const more = targets.length > 1 ? ` +${targets.length - 1}` : ''
  return `${scanner} — ${targets[0]}${more}`
}

/** User-terms text for a refusal the API reports by code; else the server's text. */
export function quickScanErrorText(error: unknown, t: Translate, fallback: string): string {
  const code = (error as { code?: unknown } | null)?.code
  if (typeof code === 'string') {
    const key = `scans.quick.err.${code}`
    const text = t(key, '')
    if (text && text !== key) return text
  }
  return getErrorMessage(error, fallback)
}

export function QuickScanDialog({ open, onOpenChange, onSuccess }: QuickScanDialogProps) {
  const { t } = useTranslation()
  const [targets, setTargets] = useState<string[]>([])
  const [scannerName, setScannerName] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [refused, setRefused] = useState<ScopeRefusal[]>([])
  const [readiness, setReadiness] = useState<ScanReadiness | null>(null)
  const [started, setStarted] = useState<QuickScanResponse | null>(null)
  const [saveName, setSaveName] = useState('')
  const [savedName, setSavedName] = useState<string | null>(null)
  // What stopped the last press of Start: the button stays enabled, the dialog says why.
  const [problem, setProblem] = useState<{
    field: 'targets' | 'scanner' | 'fix'
    text: string
  } | null>(null)

  const { trigger: quickScan } = useQuickScan()
  const { trigger: saveQuickScan, isMutating: isSaving } = useSaveQuickScan(
    started?.scan_id ?? null
  )

  const pasted = useMemo(() => parsePastedTargets(targets), [targets])
  const targetList = pasted.targets

  const handleSubmit = async (override?: { targets: string[]; scanner: string }) => {
    const sendTargets = override?.targets ?? targetList
    const sendScanner = override?.scanner ?? scannerName
    if (sendTargets.length === 0) {
      toast.error(t('scans.quick.needTarget'))
      return
    }
    if (!sendScanner) {
      toast.error(t('scans.err.scanner'))
      return
    }

    setIsSubmitting(true)
    setRefused([])
    try {
      const result = await quickScan({ targets: sendTargets, scanner_name: sendScanner })
      toast.success(t('scans.quick.started', undefined, { count: sendTargets.length }))
      await Promise.all([invalidateScanRunsCache(), invalidateScanManagementStatsCache()])
      setStarted(result ?? null)
      setSaveName(defaultSaveName(sendScanner, sendTargets, t))
      onSuccess?.()
    } catch (error) {
      const scopeRefused = refusedFromError(error)
      if (scopeRefused.length > 0) {
        setRefused(scopeRefused)
        return
      }
      toast.error(quickScanErrorText(error, t, t('scans.quick.startFailed')))
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleSave = async () => {
    const name = saveName.trim()
    if (!name || !started) return
    try {
      await saveQuickScan({ name })
      await invalidateScanConfigsCache()
      setSavedName(name)
      toast.success(t('scans.quick.saved', undefined, { name }))
    } catch (error) {
      toast.error(getErrorMessage(error, t('scans.quick.saveFailed')))
    }
  }

  const startPressed = () => {
    const invalid =
      targetList.length === 0
        ? { field: 'targets' as const, text: t('scans.quick.needTarget') }
        : pasted.invalid.length > 0 || readiness?.state === 'blocked'
          ? { field: 'fix' as const, text: t('scans.quick.fixFirst') }
          : !scannerName
            ? { field: 'scanner' as const, text: t('scans.err.scanner') }
            : null
    setProblem(invalid)
    if (invalid) {
      if (invalid.field === 'scanner') document.getElementById('quick-scanner')?.focus()
      return
    }
    void handleSubmit()
  }

  const handleClose = () => {
    setProblem(null)
    setRefused([])
    setTargets([])
    setScannerName('')
    setStarted(null)
    setSaveName('')
    setSavedName(null)
    onOpenChange(false)
  }

  return (
    <FormDialog
      open={open}
      onOpenChange={(o) => !o && handleClose()}
      size="lg"
      title={t('scans.quick.title')}
      description={t('scans.quick.description')}
      data-testid="quick-scan-dialog"
      {...(started
        ? {
            // The run has started: the one action closes; saving it is optional.
            onSubmit: handleClose,
            submitLabel: t('scans.quick.done'),
            cancelLabel: null,
          }
        : {
            onSubmit: startPressed,
            submitting: isSubmitting,
            error: problem && problem.field !== 'scanner' ? problem.text : null,
            submitLabel: isSubmitting ? (
              t('scans.common.starting')
            ) : (
              <>
                <Zap aria-hidden />
                {t('scans.quick.start')}
              </>
            ),
          })}
    >
      {started ? (
        <FormStack>
          <div className="flex items-start gap-3 rounded-lg border p-3">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
            <div className="space-y-1 text-sm">
              <p className="font-medium">
                {t('scans.quick.startedOn', undefined, { count: started.target_count })}
              </p>
              <p className="text-muted-foreground">{t('scans.quick.followRuns')}</p>
            </div>
          </div>

          {savedName ? (
            <p className="text-sm">
              {t('scans.quick.savedAsPrefix')}{' '}
              <Link href={`/scans/${started.scan_id}`} className="font-medium underline">
                {savedName}
              </Link>
              . {t('scans.quick.savedAsSuffix')}
            </p>
          ) : (
            <FormField
              id="quick-save-name"
              label={t('scans.quick.saveAsScan')}
              required={false}
              hint={t('scans.quick.saveHint')}
            >
              {(control) => (
                <div className="flex gap-2">
                  <Input
                    {...control}
                    value={saveName}
                    onChange={(e) => setSaveName(e.target.value)}
                    maxLength={200}
                    onKeyDown={(e) => {
                      // Enter here saves; it must not reach the dialog's Done.
                      if (e.key === 'Enter') {
                        e.preventDefault()
                        if (!isSaving && saveName.trim()) void handleSave()
                      }
                    }}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleSave}
                    disabled={isSaving || !saveName.trim()}
                  >
                    {isSaving ? (
                      <Loader2 className="animate-spin" aria-hidden />
                    ) : (
                      <Save aria-hidden />
                    )}
                    {t('scans.quick.save')}
                  </Button>
                </div>
              )}
            </FormField>
          )}
        </FormStack>
      ) : (
        <FormStack>
          {/* Targets: the same paste source and summary as New Scan */}
          <PasteSource
            value={targets}
            onChange={(v) => {
              setTargets(v)
              setProblem(null)
            }}
          />

          {/* Scanner: the tool registry's active scanners */}
          <FormField
            id="quick-scanner"
            label={t('scans.basic.scanner')}
            error={problem?.field === 'scanner' ? problem.text : undefined}
          >
            {(control) => (
              <ScannerSelect
                {...control}
                value={scannerName}
                onChange={(v) => {
                  setScannerName(v)
                  setProblem(null)
                }}
              />
            )}
          </FormField>

          {refused.length > 0 ? (
            <ScopeRefusalPanel refused={refused} />
          ) : (
            <SelectionSummary
              targets={targetList}
              chips={targetList.map((target) => ({
                key: target,
                label: target,
                kind: 'typed' as const,
                onRemove: () =>
                  setTargets([
                    ...targetList.filter((x) => x !== target),
                    ...pasted.invalid.map((bad) => bad.input),
                  ]),
              }))}
              groupCount={0}
              invalidCount={pasted.invalid.length}
              scannerName={scannerName}
              onReadinessChange={setReadiness}
              review={
                <QuickScanPreviewPanel
                  targets={targetList}
                  scannerName={scannerName}
                  discovering={isSubmitting}
                  onDiscover={(tool, root) => {
                    void handleSubmit({ targets: [root], scanner: tool })
                  }}
                />
              }
            />
          )}
        </FormStack>
      )}
    </FormDialog>
  )
}
