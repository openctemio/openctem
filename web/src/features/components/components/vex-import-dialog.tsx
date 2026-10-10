'use client'

/**
 * VEX document import: choose the file (OpenVEX, CSAF VEX or CycloneDX VEX)
 * and, optionally, the asset it is about; preview what would be stored
 * (nothing is written), then import.
 */

import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, FileJson, Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { importVexDocument, type VexImportResult } from '../api/vex'
import { AssetChooser, type ChosenAsset } from './asset-chooser'
import { useVexLabels } from './vex-labels'

/** The API refuses larger documents; checked before reading the file. */
export const MAX_VEX_BYTES = 5 * 1024 * 1024

type Step = 'choose' | 'preview' | 'done'

export async function readVexFile(file: File): Promise<unknown> {
  if (file.size > MAX_VEX_BYTES) throw new Error('too_large')
  const text =
    typeof file.text === 'function'
      ? await file.text()
      : await new Promise<string>((resolve, reject) => {
          const reader = new FileReader()
          reader.onload = () => resolve(String(reader.result ?? ''))
          reader.onerror = () => reject(reader.error)
          reader.readAsText(file)
        })
  try {
    return JSON.parse(text)
  } catch {
    throw new Error('not_json')
  }
}

export function VexImportDialog({
  open,
  onOpenChange,
  onImported,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onImported?: () => void
}) {
  const { t } = useTranslation()
  const [step, setStep] = useState<Step>('choose')
  const [asset, setAsset] = useState<ChosenAsset | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [doc, setDoc] = useState<unknown>(null)
  const [result, setResult] = useState<VexImportResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) {
      setStep('choose')
      setAsset(null)
      setFile(null)
      setDoc(null)
      setResult(null)
      setError(null)
    }
  }, [open])

  const fileError = (e: unknown) =>
    e instanceof Error && e.message === 'too_large'
      ? t('components.vexImport.tooLarge', 'The file is larger than 5 MB.')
      : e instanceof Error && e.message === 'not_json'
        ? t('components.vexImport.notJson', 'The file is not valid JSON.')
        : getErrorMessage(
            e,
            t('components.vexImport.failed', 'The VEX document could not be read.')
          )

  const run = async (dryRun: boolean) => {
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      const parsed = doc ?? (await readVexFile(file))
      setDoc(parsed)
      setResult(await importVexDocument(parsed, asset?.id ?? null, dryRun))
      setStep(dryRun ? 'preview' : 'done')
      if (!dryRun) onImported?.()
    } catch (e) {
      setError(fileError(e))
    } finally {
      setBusy(false)
    }
  }

  const stepLabel = {
    choose: t('components.vexImport.step1', 'Step 1 of 3: choose the file'),
    preview: t('components.vexImport.step2', 'Step 2 of 3: check the preview'),
    done: t('components.vexImport.step3', 'Step 3 of 3: imported'),
  }[step]

  const writes = result ? result.created + result.updated : 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('components.vexImport.title', 'Import a VEX document')}</DialogTitle>
          <DialogDescription>{stepLabel}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {step === 'choose' && (
            <>
              <div className="space-y-2">
                <Label htmlFor="vex-file">{t('components.vexImport.file', 'VEX document')}</Label>
                <input
                  id="vex-file"
                  type="file"
                  accept=".json,application/json"
                  className="block w-full text-sm file:me-3 file:rounded-md file:border file:bg-muted file:px-3 file:py-1.5 file:text-sm"
                  onChange={(e) => {
                    setFile(e.target.files?.[0] ?? null)
                    setDoc(null)
                    setError(null)
                  }}
                />
                <p className="text-xs text-muted-foreground">
                  {t(
                    'components.vexImport.formats',
                    'OpenVEX, CSAF VEX or CycloneDX VEX, JSON, up to 5 MB. Statements about packages that are not in the inventory are skipped.'
                  )}
                </p>
              </div>
              <div className="space-y-2">
                <Label>
                  {t('components.vexImport.asset', 'Asset the document is about (optional)')}
                </Label>
                <AssetChooser value={asset} onChange={setAsset} enabled={open} />
                <p className="text-xs text-muted-foreground">
                  {t(
                    'components.vexImport.assetHelp',
                    'Without an asset the statements apply to every asset, which needs access to every asset. Statements about components inside a product need an asset.'
                  )}
                </p>
              </div>
            </>
          )}

          {step !== 'choose' && result && <VexImportSummary result={result} />}

          {error && (
            <p
              role="alert"
              className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          {step === 'choose' && (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button onClick={() => run(true)} disabled={!file || busy}>
                {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
                {t('components.vexImport.preview', 'Preview')}
              </Button>
            </>
          )}
          {step === 'preview' && (
            <>
              <Button variant="outline" onClick={() => setStep('choose')} disabled={busy}>
                {t('components.vexImport.back', 'Back')}
              </Button>
              <Button
                onClick={() => run(false)}
                disabled={busy || !result || result.statements === 0}
              >
                {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
                {t('components.vexImport.confirm', 'Import {count} statements', { count: writes })}
              </Button>
            </>
          )}
          {step === 'done' && (
            <Button onClick={() => onOpenChange(false)}>
              {t('components.vexImport.close', 'Done')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold tabular-nums">{value}</div>
    </div>
  )
}

export function VexImportSummary({ result }: { result: VexImportResult }) {
  const { t } = useTranslation()
  const labels = useVexLabels()
  const action = (a: string) =>
    ({
      create: t('components.vexImport.action.create', 'new'),
      update: t('components.vexImport.action.update', 'updated'),
      unchanged: t('components.vexImport.action.unchanged', 'unchanged'),
    })[a] ?? a
  // The API reports why a statement was skipped in English; known reasons are translated.
  const reason = (r: string) =>
    ({
      'package not in the inventory': t(
        'components.vexImport.reason.notInInventory',
        'package not in the inventory'
      ),
      'product has no package URL': t(
        'components.vexImport.reason.noPurl',
        'product has no package URL'
      ),
      'invalid package URL': t('components.vexImport.reason.invalidPurl', 'invalid package URL'),
      'no usable vulnerability id': t(
        'components.vexImport.reason.noVulnId',
        'no usable vulnerability id'
      ),
      'statement about components inside a product: choose the target asset': t(
        'components.vexImport.reason.needsAsset',
        'statement about components inside a product: choose the target asset'
      ),
      'a statement written in the organization covers this already': t(
        'components.vexImport.reason.manualExists',
        'a statement written in the organization covers this already'
      ),
    })[r] ?? r
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {result.dry_run ? (
          <FileJson className="h-4 w-4 text-muted-foreground" aria-hidden />
        ) : (
          <CheckCircle2 className="h-4 w-4 text-success" aria-hidden />
        )}
        <Badge variant="outline" className="font-mono text-[11px]">
          {result.format}
        </Badge>
        {result.dry_run && (
          <Badge variant="secondary">
            {t('components.vexImport.previewBadge', 'Preview: nothing written')}
          </Badge>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label={t('components.vexImport.created', 'New')} value={result.created} />
        <Stat label={t('components.vexImport.updated', 'Updated')} value={result.updated} />
        <Stat label={t('components.vexImport.unchanged', 'Unchanged')} value={result.unchanged} />
        <Stat
          label={t('components.vexImport.skippedCount', 'Skipped')}
          value={result.skipped_total}
        />
      </div>
      {!result.dry_run && (
        <p className="text-sm">
          {t('components.vexImport.applied', '{closed} findings closed, {reopened} reopened.', {
            closed: result.applied.closed,
            reopened: result.applied.reopened,
          })}
        </p>
      )}
      {result.items.length > 0 && (
        <ul className="max-h-48 space-y-1 overflow-y-auto rounded-md border p-2 text-xs">
          {result.items.map((i, n) => (
            <li key={`${i.vuln_id}-${i.purl}-${n}`} className="flex flex-wrap gap-2">
              <span className="font-mono">{i.vuln_id}</span>
              <span className="truncate font-mono text-muted-foreground">{i.purl}</span>
              <span>{labels.status(i.status)}</span>
              <Badge variant="outline" className="font-normal">
                {action(i.action)}
              </Badge>
            </li>
          ))}
        </ul>
      )}
      {result.skipped.length > 0 && (
        <div className="space-y-1">
          <p className="text-sm font-medium">
            {t('components.vexImport.skipped', '{count} statements skipped', {
              count: result.skipped_total,
            })}
          </p>
          <ul className="max-h-40 space-y-1 overflow-y-auto rounded-md border p-2 text-xs">
            {result.skipped.map((s, n) => (
              <li key={`${s.vuln_id}-${n}`} className="flex flex-wrap gap-2">
                {s.vuln_id && <span className="font-mono">{s.vuln_id}</span>}
                {s.purl && <span className="truncate font-mono">{s.purl}</span>}
                <span className="text-muted-foreground">{reason(s.reason)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
