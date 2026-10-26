'use client'

/**
 * Import results: upload a file another tool exported (Nessus, Qualys,
 * CycloneDX, SPDX, OSV, CSAF, OpenVEX, DefectDojo, or a ZIP of them). The
 * server detects the format; Preview parses and counts without writing,
 * Import ingests with the uploader's rights. Every value shown comes from the
 * uploaded file and is rendered as text.
 */

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { toast } from 'sonner'
import { safeText } from '@/lib/api/error-message'
import { AlertTriangle, FileUp, Loader2 } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'

import {
  FindingImportError,
  importFindings,
  type FindingImportResponse,
  type ImportMinSeverity,
  type ImportFileResponse,
} from '../api/finding-import-api'
import {
  formatLabel,
  importTotals,
  placeText,
  severityCounts,
  vexModeText,
} from '../lib/import-results'
import { MappingFormatField } from './mapping-format-field'
import { ReceiptSummary, RecentImports } from './receipt-summary'

const ACCEPT_RECON = '.zip,application/zip'
const ACCEPT = '.nessus,.xml,.json,.zip,application/xml,text/xml,application/json,application/zip'
/** A saved import mapping reads CSV, JSON, JSON Lines or XML. */
const ACCEPT_MAPPED =
  '.csv,.tsv,.json,.jsonl,.ndjson,.xml,.txt,text/csv,application/json,application/xml,text/xml'

interface ImportResultsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Called after a successful import (not after a preview). */
  onImported?: () => void
  /** Drop findings below this severity (e.g. 'low' skips informational results). */
  minSeverity?: ImportMinSeverity
}

export function ImportResultsDialog({
  open,
  onOpenChange,
  onImported,
  minSeverity,
}: ImportResultsDialogProps) {
  const { t } = useTranslation()
  const [file, setFile] = useState<File | null>(null)
  const [kb, setKb] = useState<File | null>(null)
  // A saved import mapping as the format; empty: detect it from the file.
  const [format, setFormat] = useState('')
  // 'tool': another tool's export (detected). 'recon': a reconFTW results
  // directory as a ZIP; the server detects it from the layout.
  const [source, setSource] = useState<'tool' | 'recon'>('tool')
  const [busy, setBusy] = useState<'preview' | 'import' | null>(null)
  const [preview, setPreview] = useState<FindingImportResponse | null>(null)
  const [result, setResult] = useState<FindingImportResponse | null>(null)
  const [error, setError] = useState<{ message: string; file?: ImportFileResponse } | null>(null)

  function reset() {
    setFile(null)
    setKb(null)
    setFormat('')
    setSource('tool')
    setPreview(null)
    setResult(null)
    setError(null)
  }

  async function run(dryRun: boolean) {
    if (!file) return
    setBusy(dryRun ? 'preview' : 'import')
    setError(null)
    try {
      const resp = await importFindings({
        file,
        knowledgeBase: format || source === 'recon' ? null : kb,
        dryRun,
        minSeverity,
        format: source === 'recon' ? undefined : format || undefined,
      })
      if (dryRun) {
        setPreview(resp)
      } else {
        setResult(resp)
        const totals = importTotals(resp.files ?? [])
        toast.success(
          t(
            'findings.importResults.imported',
            'Imported {created} new and {updated} updated findings',
            { created: totals.created, updated: totals.updated }
          )
        )
        onImported?.()
      }
    } catch (e) {
      if (e instanceof FindingImportError && e.code) {
        // A stored upload the server could not import: a fixed code.
        setError({
          message: t(
            'findings.importResults.notApplied',
            'The upload was stored but could not be imported ({code}). Nothing was changed; try again.',
            { code: e.code }
          ),
        })
      } else if (e instanceof FindingImportError) {
        setError({
          message: safeText(e.message, t('findings.importResults.failed', 'The import failed')),
          file: e.file,
        })
      } else {
        setError({ message: t('findings.importResults.failed', 'The import failed') })
      }
      if (dryRun) setPreview(null)
    } finally {
      setBusy(null)
    }
  }

  const shown = result ?? preview
  const needsKb = preview?.files?.some((f) => f.format === 'qualys') ?? false

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset()
        onOpenChange(o)
      }}
    >
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('findings.importResults.title', 'Import results')}</DialogTitle>
          <DialogDescription>
            {t(
              'findings.importResults.description',
              'Upload results another tool exported: Nessus, Qualys, SARIF, trivy, grype, semgrep, gitleaks, nuclei, ZAP, vuls, CycloneDX, SPDX, OSV, CSAF, OpenVEX or DefectDojo, or a ZIP of them. The format is detected from the file. Findings land only on assets you can change, and an import never resolves other findings.'
            )}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="grid gap-4">
          {!result && (
            <div className="space-y-3">
              <RadioGroup
                value={source}
                onValueChange={(v) => {
                  setSource(v as 'tool' | 'recon')
                  setFormat('')
                  setFile(null)
                  setPreview(null)
                  setError(null)
                }}
                aria-label={t('findings.importResults.sourceLabel', 'What you are importing')}
              >
                <div className="flex items-center gap-2">
                  <RadioGroupItem value="tool" id="import-source-tool" />
                  <Label htmlFor="import-source-tool">
                    {t('findings.importResults.sourceTool', 'Results from a security tool')}
                  </Label>
                </div>
                <div className="flex items-center gap-2">
                  <RadioGroupItem value="recon" id="import-source-recon" />
                  <Label htmlFor="import-source-recon">
                    {t('findings.importResults.sourceRecon', 'Recon results (reconFTW directory)')}
                  </Label>
                </div>
              </RadioGroup>
              {source === 'recon' && (
                <p className="text-muted-foreground text-xs" data-testid="recon-hint">
                  {t(
                    'findings.importResults.reconHint',
                    'Upload the results directory of a reconFTW run as one ZIP. Preview first: it lists the hosts outside your scope, which wait for review and are never scanned, the files skipped on purpose (people and credential data) and the files that are not recognized. A recon import never closes findings.'
                  )}
                </p>
              )}
              {source === 'tool' && (
                <MappingFormatField
                  value={format}
                  onChange={(v) => {
                    setFormat(v)
                    setPreview(null)
                    setError(null)
                  }}
                />
              )}
              <div className="space-y-1">
                <Label htmlFor="import-file">{t('findings.importResults.file', 'File')}</Label>
                <Input
                  id="import-file"
                  type="file"
                  accept={source === 'recon' ? ACCEPT_RECON : format ? ACCEPT_MAPPED : ACCEPT}
                  onChange={(e) => {
                    setFile(e.target.files?.[0] ?? null)
                    setPreview(null)
                    setError(null)
                  }}
                />
              </div>
              {!format && source === 'tool' && (
                <div className="space-y-1">
                  <Label htmlFor="import-kb">
                    {t('findings.importResults.qualysKb', 'Qualys KnowledgeBase')}{' '}
                    <span className="text-muted-foreground">
                      ({t('findings.importResults.optional', 'optional')})
                    </span>
                  </Label>
                  <Input
                    id="import-kb"
                    type="file"
                    accept=".xml,application/xml,text/xml"
                    onChange={(e) => {
                      setKb(e.target.files?.[0] ?? null)
                      setPreview(null)
                    }}
                  />
                  {needsKb && !kb && (
                    <p className="text-muted-foreground text-xs">
                      {t(
                        'findings.importResults.noKbHint',
                        'Without the KnowledgeBase, Qualys detections keep their QID but have no title, CVEs or CVSS.'
                      )}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="border-destructive/50 text-destructive rounded-md border p-3 text-sm"
            >
              <div className="flex items-center gap-2 font-medium">
                <AlertTriangle className="h-4 w-4" />
                <span>{error.message}</span>
              </div>
              {error.file?.issues && error.file.issues.length > 0 && (
                <IssueList issues={error.file.issues} />
              )}
            </div>
          )}

          {shown && (
            <div className="space-y-3" data-testid="import-summary">
              <p className="text-muted-foreground text-xs">
                {shown.dry_run
                  ? t('findings.importResults.previewNote', 'Preview: nothing was written.') + ' '
                  : ''}
                {vexModeText(t, shown.vex_mode, shown.vex_can_close)}
              </p>
              {!shown.dry_run && shown.receipt && <ReceiptSummary receipt={shown.receipt} />}
              {(shown.files ?? []).map((f, i) => (
                <FileSummary key={`${f.name}-${i}`} file={f} dryRun={shown.dry_run ?? false} />
              ))}
            </div>
          )}
          {!shown && <RecentImports />}
        </DialogBody>

        <DialogFooter>
          {result ? (
            <Button onClick={() => onOpenChange(false)}>
              {t('findings.importResults.close', 'Close')}
            </Button>
          ) : (
            <>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!file || busy !== null}
                onClick={() => run(true)}
              >
                {busy === 'preview' && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {t('findings.importResults.preview', 'Preview')}
              </Button>
              <Button
                type="button"
                disabled={
                  !file ||
                  !preview ||
                  busy !== null ||
                  importTotals(preview.files ?? []).failed === (preview.files ?? []).length
                }
                onClick={() => run(false)}
              >
                {busy === 'import' ? (
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                ) : (
                  <FileUp className="me-2 h-4 w-4" />
                )}
                {t('findings.importResults.import', 'Import')}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function IssueList({ issues }: { issues: NonNullable<ImportFileResponse['issues']> }) {
  return (
    <ul className="mt-2 max-h-40 list-disc space-y-0.5 overflow-y-auto ps-5 text-xs">
      {issues.map((is, i) => (
        <li key={i} className="break-words">
          {placeText(is)}
        </li>
      ))}
    </ul>
  )
}

function Count({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border px-2 py-1">
      <div className="text-muted-foreground text-[11px]">{label}</div>
      <div className="font-medium tabular-nums">{value}</div>
    </div>
  )
}

function FileSummary({ file, dryRun }: { file: ImportFileResponse; dryRun: boolean }) {
  const { t } = useTranslation()
  const stats = file.stats
  const sev = severityCounts(file)
  return (
    <div className="space-y-2 rounded-md border p-3 text-sm" data-testid="import-file">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium break-all">{file.name}</span>
        <Badge variant="outline">{formatLabel(file.format)}</Badge>
      </div>
      {file.error ? (
        <p className="text-destructive text-xs" role="alert">
          {placeText(file.error)}
        </p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Count
              label={t('findings.importResults.assets', 'Assets')}
              value={stats?.assets ?? 0}
            />
            <Count
              label={t('findings.importResults.findings', 'Findings')}
              value={stats?.findings ?? 0}
            />
            <Count
              label={t('findings.importResults.components', 'Components')}
              value={stats?.components ?? 0}
            />
            <Count
              label={t('findings.importResults.vexStatements', 'VEX statements')}
              value={stats?.statements ?? 0}
            />
          </div>
          {sev.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {sev.map((s) => (
                <Badge key={s.severity} variant="secondary">
                  {s.severity}: {s.count}
                </Badge>
              ))}
            </div>
          )}
          {file.layout && <ReconSummary file={file} />}
          {(stats?.skipped ?? 0) > 0 && (
            <p className="text-muted-foreground text-xs">
              {t('findings.importResults.skipped', '{count} records skipped.', {
                count: stats?.skipped ?? 0,
              })}
            </p>
          )}
          {file.vex && (
            <p className="text-xs">
              {t('findings.importResults.vexMatched', 'VEX: {count} matching findings', {
                count: file.vex.matched ?? 0,
              })}
              {dryRun
                ? t('findings.importResults.vexWouldClose', ', {count} would be requested', {
                    count: file.vex.would_close ?? 0,
                  })
                : t(
                    'findings.importResults.vexStored',
                    ', stored on {stored}, {requested} false positive requests',
                    {
                      stored: file.vex.stored ?? 0,
                      requested: file.vex.requested ?? 0,
                    }
                  ) +
                  (file.vex.would_close
                    ? t('findings.importResults.vexWouldClose', ', {count} would be requested', {
                        count: file.vex.would_close ?? 0,
                      })
                    : '')}
              {(file.vex.unmatchable ?? 0) > 0
                ? t(
                    'findings.importResults.vexUnmatchable',
                    '; {count} statements cannot be matched (no package URL)',
                    { count: file.vex.unmatchable ?? 0 }
                  )
                : ''}
            </p>
          )}
          {file.ingest && (
            <p className="text-xs">
              {t(
                'findings.importResults.ingestSummary',
                '{created} findings created, {updated} updated, {assets} assets created',
                {
                  created: file.ingest.findings_created ?? 0,
                  updated: file.ingest.findings_updated ?? 0,
                  assets: file.ingest.assets_created ?? 0,
                }
              )}
              {(file.ingest.assets_skipped_out_of_scope ?? 0) > 0
                ? t(
                    'findings.importResults.ingestSkipped',
                    '; {count} hosts skipped (outside the assets you can change)',
                    { count: file.ingest.assets_skipped_out_of_scope ?? 0 }
                  )
                : ''}
            </p>
          )}
        </>
      )}
      {file.issues && file.issues.length > 0 && (
        <div>
          <p className="text-xs font-medium">
            {t('findings.importResults.problems', '{count} problems', {
              count: file.issues.length,
            })}
          </p>
          <IssueList issues={file.issues} />
        </div>
      )}
      {file.unmapped && file.unmapped.length > 0 && (
        <PathList
          paths={file.unmapped.map((p) => ({ path: p }))}
          total={file.unmapped_total ?? file.unmapped.length}
          label={
            file.layout
              ? t('findings.importResults.unmappedFiles', '{count} files not recognized', {
                  count: file.unmapped_total ?? file.unmapped.length,
                })
              : t('findings.importResults.unmapped', '{count} source fields not recognized', {
                  count: file.unmapped.length,
                })
          }
        />
      )}
    </div>
  )
}

/** A collapsible list of paths from an uploaded file, each with an optional reason. */
function PathList({
  paths,
  total,
  label,
}: {
  paths: { path: string; reason?: string }[]
  total: number
  label: string
}) {
  const { t } = useTranslation()
  return (
    <Collapsible>
      <CollapsibleTrigger className="text-muted-foreground text-xs underline">
        {label}
      </CollapsibleTrigger>
      <CollapsibleContent>
        <ul className="mt-1 max-h-32 overflow-y-auto font-mono text-[11px]">
          {paths.map((p) => (
            <li key={p.path} className="break-all">
              {p.path}
              {p.reason ? (
                <span className="text-muted-foreground font-sans"> ({p.reason})</span>
              ) : null}
            </li>
          ))}
        </ul>
        {total > paths.length && (
          <p className="text-muted-foreground mt-1 text-[11px]">
            {t('findings.importResults.listCut', 'Showing {shown} of {total}.', {
              shown: paths.length,
              total,
            })}
          </p>
        )}
      </CollapsibleContent>
    </Collapsible>
  )
}

/** What a recon directory import adds to the summary: layout, endpoints, candidates, skipped files. */
function ReconSummary({ file }: { file: ImportFileResponse }) {
  const { t } = useTranslation()
  const skipped = file.skipped_by_policy ?? []
  return (
    <div className="space-y-2" data-testid="recon-summary">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Count
          label={t('findings.importResults.endpoints', 'Endpoints')}
          value={file.stats?.endpoints ?? 0}
        />
        <Count
          label={t('findings.importResults.candidates', 'Hosts outside your scope')}
          value={file.candidates ?? 0}
        />
      </div>
      {(file.candidates ?? 0) > 0 && (
        <p className="text-xs" data-testid="recon-candidates">
          {t(
            'findings.importResults.candidatesNote',
            '{count} hosts are outside your scope. They wait for review, are never scanned, and their findings are tagged candidate.',
            { count: file.candidates ?? 0 }
          )}
        </p>
      )}
      {skipped.length > 0 && (
        <PathList
          paths={skipped.map((p) => ({ path: p.path ?? '', reason: p.reason }))}
          total={file.skipped_by_policy_total ?? skipped.length}
          label={t('findings.importResults.skippedByPolicy', '{count} files skipped on purpose', {
            count: file.skipped_by_policy_total ?? skipped.length,
          })}
        />
      )}
    </div>
  )
}
