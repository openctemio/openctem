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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import { SelectionSummary } from './target-picker/selection-summary'
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

export function QuickScanDialog({ open, onOpenChange, onSuccess }: QuickScanDialogProps) {
  const { t } = useTranslation()
  const [targets, setTargets] = useState<string[]>([])
  const [scannerName, setScannerName] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [refused, setRefused] = useState<ScopeRefusal[]>([])
  const [started, setStarted] = useState<QuickScanResponse | null>(null)
  const [saveName, setSaveName] = useState('')
  const [savedName, setSavedName] = useState<string | null>(null)

  const { trigger: quickScan } = useQuickScan()
  const { trigger: saveQuickScan, isMutating: isSaving } = useSaveQuickScan(
    started?.scan_id ?? null
  )

  const pasted = useMemo(() => parsePastedTargets(targets), [targets])
  const targetList = pasted.targets

  const handleSubmit = async () => {
    if (targetList.length === 0) {
      toast.error(t('scans.quick.needTarget'))
      return
    }
    if (!scannerName) {
      toast.error(t('scans.err.scanner'))
      return
    }

    setIsSubmitting(true)
    setRefused([])
    try {
      const result = await quickScan({ targets: targetList, scanner_name: scannerName })
      toast.success(t('scans.quick.started', undefined, { count: targetList.length }))
      await Promise.all([invalidateScanRunsCache(), invalidateScanManagementStatsCache()])
      setStarted(result ?? null)
      setSaveName(defaultSaveName(scannerName, targetList, t))
      onSuccess?.()
    } catch (error) {
      const scopeRefused = refusedFromError(error)
      if (scopeRefused.length > 0) {
        setRefused(scopeRefused)
        return
      }
      toast.error(getErrorMessage(error, t('scans.quick.startFailed')))
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

  const handleClose = () => {
    setRefused([])
    setTargets([])
    setScannerName('')
    setStarted(null)
    setSaveName('')
    setSavedName(null)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('scans.quick.title')}</DialogTitle>
          <DialogDescription>{t('scans.quick.description')}</DialogDescription>
        </DialogHeader>

        {started ? (
          <>
            <DialogBody className="space-y-4">
              <div className="flex items-start gap-3 rounded-lg border p-3">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />
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
                <div className="space-y-2">
                  <Label htmlFor="quick-save-name">{t('scans.quick.saveAsScan')}</Label>
                  <div className="flex gap-2">
                    <Input
                      id="quick-save-name"
                      value={saveName}
                      onChange={(e) => setSaveName(e.target.value)}
                      maxLength={200}
                    />
                    <Button
                      variant="outline"
                      onClick={handleSave}
                      disabled={isSaving || !saveName.trim()}
                    >
                      {isSaving ? (
                        <Loader2 className="me-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Save className="me-2 h-4 w-4" />
                      )}
                      {t('scans.quick.save')}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">{t('scans.quick.saveHint')}</p>
                </div>
              )}
            </DialogBody>
            <DialogFooter>
              <Button onClick={handleClose}>{t('scans.quick.done')}</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogBody className="space-y-4">
              {/* Targets: the same paste source and summary as New Scan */}
              <PasteSource value={targets} onChange={setTargets} />

              {/* Scanner: the tool registry's active scanners */}
              <div className="space-y-2">
                <Label htmlFor="quick-scanner">{t('scans.basic.scanner')}</Label>
                <ScannerSelect id="quick-scanner" value={scannerName} onChange={setScannerName} />
              </div>

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
                />
              )}
            </DialogBody>

            <DialogFooter>
              <Button variant="outline" onClick={handleClose} disabled={isSubmitting}>
                {t('common.cancel')}
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={
                  isSubmitting ||
                  targetList.length === 0 ||
                  pasted.invalid.length > 0 ||
                  !scannerName
                }
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="me-2 h-4 w-4 animate-spin" />
                    {t('scans.common.starting')}
                  </>
                ) : (
                  <>
                    <Zap className="me-2 h-4 w-4" />
                    {t('scans.quick.start')}
                  </>
                )}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
