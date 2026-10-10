'use client'

/**
 * SBOM import wizard: choose the asset and the file, preview what the import
 * would change (nothing is written), then import.
 */

import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, FileJson, Loader2 } from 'lucide-react'
import Link from '@/components/link'
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
import { importSbom } from '../api/hooks'
import type { SbomImportResult } from '../api/types'
import { AssetChooser, type ChosenAsset } from './asset-chooser'

/** The API refuses larger documents; checked before reading the file. */
export const MAX_SBOM_BYTES = 50 * 1024 * 1024

type Step = 'choose' | 'preview' | 'done'

function fileText(file: File): Promise<string> {
  if (typeof file.text === 'function') return file.text()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

export async function readSbomFile(file: File): Promise<unknown> {
  if (file.size > MAX_SBOM_BYTES) throw new Error('too_large')
  const text = await fileText(file)
  try {
    return JSON.parse(text)
  } catch {
    throw new Error('not_json')
  }
}

export function SbomImportDialog({
  open,
  onOpenChange,
  onImported,
  initialAsset = null,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onImported?: () => void
  initialAsset?: ChosenAsset | null
}) {
  const { t } = useTranslation()
  const [step, setStep] = useState<Step>('choose')
  const [asset, setAsset] = useState<ChosenAsset | null>(initialAsset)
  const [file, setFile] = useState<File | null>(null)
  const [doc, setDoc] = useState<unknown>(null)
  const [result, setResult] = useState<SbomImportResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) {
      setStep('choose')
      setFile(null)
      setDoc(null)
      setResult(null)
      setError(null)
      setAsset(initialAsset)
    }
  }, [open, initialAsset])

  const fileError = (e: unknown) =>
    e instanceof Error && e.message === 'too_large'
      ? t('components.import.tooLarge', 'The file is larger than 50 MB.')
      : e instanceof Error && e.message === 'not_json'
        ? t(
            'components.import.notJson',
            'The file is not valid JSON (CycloneDX or SPDX JSON is expected).'
          )
        : getErrorMessage(e, t('components.import.failed', 'The SBOM could not be read.'))

  const preview = async () => {
    if (!asset || !file) return
    setBusy(true)
    setError(null)
    try {
      const parsed = doc ?? (await readSbomFile(file))
      setDoc(parsed)
      setResult(await importSbom(asset.id, parsed, true))
      setStep('preview')
    } catch (e) {
      setError(fileError(e))
    } finally {
      setBusy(false)
    }
  }

  const commit = async () => {
    if (!asset || doc == null) return
    setBusy(true)
    setError(null)
    try {
      setResult(await importSbom(asset.id, doc, false))
      setStep('done')
      onImported?.()
    } catch (e) {
      setError(fileError(e))
    } finally {
      setBusy(false)
    }
  }

  const stepLabel = {
    choose: t('components.import.step1', 'Step 1 of 3: choose the asset and the file'),
    preview: t('components.import.step2', 'Step 2 of 3: check the preview'),
    done: t('components.import.step3', 'Step 3 of 3: imported'),
  }[step]

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('components.import.title', 'Import an SBOM')}</DialogTitle>
          <DialogDescription>{stepLabel}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {step === 'choose' && (
            <>
              <div className="space-y-2">
                <Label>{t('components.import.asset', 'Asset the SBOM describes')}</Label>
                <AssetChooser value={asset} onChange={setAsset} enabled={open} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="sbom-file">{t('components.import.file', 'SBOM file')}</Label>
                <input
                  ref={inputRef}
                  id="sbom-file"
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
                    'components.import.formats',
                    'CycloneDX 1.4 to 1.6 or SPDX 2.2 and 2.3, JSON, up to 50 MB. Packages the file lists replace the ones recorded for the same manifest.'
                  )}
                </p>
              </div>
            </>
          )}

          {step !== 'choose' && result && (
            <ImportSummary result={result} assetName={asset?.name ?? ''} />
          )}

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
              <Button onClick={preview} disabled={!asset || !file || busy}>
                {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
                {t('components.import.preview', 'Preview')}
              </Button>
            </>
          )}
          {step === 'preview' && (
            <>
              <Button variant="outline" onClick={() => setStep('choose')} disabled={busy}>
                {t('components.import.back', 'Back')}
              </Button>
              <Button
                onClick={commit}
                disabled={busy || !result || result.components_imported === 0}
              >
                {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
                {t('components.import.confirm', 'Import {count} packages', {
                  count: result?.components_imported ?? 0,
                })}
              </Button>
            </>
          )}
          {step === 'done' && (
            <>
              {asset && (
                <Button variant="outline" asChild>
                  <Link
                    href={`/components?asset_id=${asset.id}`}
                    onClick={() => onOpenChange(false)}
                  >
                    {t('components.import.viewAsset', 'Show this asset’s packages')}
                  </Link>
                </Button>
              )}
              <Button onClick={() => onOpenChange(false)}>
                {t('components.import.close', 'Done')}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold tabular-nums">{value}</div>
    </div>
  )
}

export function ImportSummary({
  result,
  assetName,
}: {
  result: SbomImportResult
  assetName: string
}) {
  const { t } = useTranslation()
  // The API reports why an entry was skipped in English; known reasons are translated.
  const reason = (r: string) =>
    ({
      'invalid package URL': t('components.import.reason.invalidPurl', 'invalid package URL'),
      'no package URL and no usable name': t(
        'components.import.reason.noName',
        'no package URL and no usable name'
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
        <span className="font-medium">{assetName}</span>
        <Badge variant="outline" className="font-mono text-[11px]">
          {result.format === 'spdx' ? 'SPDX' : 'CycloneDX'} {result.spec_version}
        </Badge>
        {result.dry_run && (
          <Badge variant="secondary">
            {t('components.import.previewBadge', 'Preview: nothing written')}
          </Badge>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat
          label={t('components.import.packages', 'Packages')}
          value={result.components_imported}
        />
        <Stat label={t('components.import.direct', 'Direct')} value={result.direct} />
        <Stat label={t('components.import.transitive', 'Transitive')} value={result.transitive} />
        <Stat label={t('components.import.licenses', 'Licenses')} value={result.licenses_found} />
      </div>
      {result.diff && (
        <p className="text-sm">
          {t(
            'components.import.diff',
            '{added} new, {unchanged} unchanged, {removed} recorded for this asset but not in the file.',
            {
              added: result.diff.added,
              unchanged: result.diff.unchanged,
              removed: result.diff.removed,
            }
          )}
        </p>
      )}
      {result.written && (
        <p className="text-sm text-muted-foreground">
          {t(
            'components.import.written',
            '{links} packages recorded, {edges} dependency links, {removed} removed.',
            {
              links: result.written.links_written,
              edges: result.written.edges_written,
              removed: result.written.links_removed,
            }
          )}
        </p>
      )}
      {result.ecosystems.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {result.ecosystems.map((e) => (
            <Badge key={e.value} variant="outline" className="font-normal">
              {e.value} <span className="ms-1 tabular-nums text-muted-foreground">{e.count}</span>
            </Badge>
          ))}
        </div>
      )}
      {result.components_skipped > 0 && (
        <div className="space-y-1">
          <p className="text-sm font-medium">
            {t('components.import.skipped', '{count} entries skipped', {
              count: result.components_skipped,
            })}
          </p>
          <ul className="max-h-40 space-y-1 overflow-y-auto rounded-md border p-2 text-xs">
            {result.issues.map((i, n) => (
              <li key={`${i.ref}-${n}`} className="flex gap-2">
                <span className="truncate font-mono">{i.name || i.ref}</span>
                <span className="text-muted-foreground">{reason(i.reason)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
