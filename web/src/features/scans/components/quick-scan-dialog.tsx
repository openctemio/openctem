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
import Link from '@/components/link'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
import { ScopePreview } from './new-scan/scope-preview'
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
export function defaultSaveName(scanner: string, targets: string[]): string {
  if (targets.length === 0) return `${scanner} scan`
  const more = targets.length > 1 ? ` +${targets.length - 1}` : ''
  return `${scanner} — ${targets[0]}${more}`
}

export function QuickScanDialog({ open, onOpenChange, onSuccess }: QuickScanDialogProps) {
  const [targets, setTargets] = useState('')
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

  const targetList = useMemo(() => parseTargets(targets), [targets])

  const handleSubmit = async () => {
    if (targetList.length === 0) {
      toast.error('Please enter at least one target')
      return
    }
    if (!scannerName) {
      toast.error('Please choose a scanner')
      return
    }

    setIsSubmitting(true)
    setRefused([])
    try {
      const result = await quickScan({ targets: targetList, scanner_name: scannerName })
      toast.success(`Quick scan started on ${targetList.length} target(s)`)
      await Promise.all([invalidateScanRunsCache(), invalidateScanManagementStatsCache()])
      setStarted(result ?? null)
      setSaveName(defaultSaveName(scannerName, targetList))
      onSuccess?.()
    } catch (error) {
      const scopeRefused = refusedFromError(error)
      if (scopeRefused.length > 0) {
        setRefused(scopeRefused)
        return
      }
      toast.error(getErrorMessage(error, 'Failed to start the quick scan'))
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
      toast.success(`Saved as scan "${name}"`)
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to save the scan'))
    }
  }

  const handleClose = () => {
    setRefused([])
    setTargets('')
    setScannerName('')
    setStarted(null)
    setSaveName('')
    setSavedName(null)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Quick Scan</DialogTitle>
          <DialogDescription>
            Run a scanner on targets now. Nothing is saved unless you choose to.
          </DialogDescription>
        </DialogHeader>

        {started ? (
          <div className="space-y-4 py-2">
            <div className="flex items-start gap-3 rounded-lg border p-3">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" />
              <div className="space-y-1 text-sm">
                <p className="font-medium">Scan started on {started.target_count} target(s)</p>
                <p className="text-muted-foreground">
                  Follow it under Runs. It is not saved as a scan configuration.
                </p>
              </div>
            </div>

            {savedName ? (
              <p className="text-sm">
                Saved as{' '}
                <Link href={`/scans/${started.scan_id}`} className="font-medium underline">
                  {savedName}
                </Link>
                . You can schedule it from there.
              </p>
            ) : (
              <div className="space-y-2">
                <Label htmlFor="quick-save-name">Save as scan</Label>
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
                    Save
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Keeps these targets and this scanner as a configuration you can run again or
                  schedule.
                </p>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <Button onClick={handleClose}>Done</Button>
            </div>
          </div>
        ) : (
          <>
            <div className="space-y-4 py-2">
              {/* Targets */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="quick-targets">Targets</Label>
                  {targetList.length > 0 && (
                    <span className="text-xs text-muted-foreground">
                      {targetList.length} target{targetList.length !== 1 ? 's' : ''}
                    </span>
                  )}
                </div>
                <Textarea
                  id="quick-targets"
                  placeholder={'example.com\n192.168.1.1\nhttps://api.example.com'}
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  rows={5}
                  className="font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">
                  Enter targets separated by newlines, commas, or semicolons.
                </p>
              </div>

              {refused.length > 0 ? (
                <ScopeRefusalPanel refused={refused} />
              ) : (
                <ScopePreview targets={targetList} />
              )}

              {/* Scanner: the tool registry's active scanners */}
              <div className="space-y-2">
                <Label htmlFor="quick-scanner">Scanner</Label>
                <ScannerSelect id="quick-scanner" value={scannerName} onChange={setScannerName} />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={handleClose} disabled={isSubmitting}>
                Cancel
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={isSubmitting || targetList.length === 0 || !scannerName}
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="me-2 h-4 w-4 animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Zap className="me-2 h-4 w-4" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
