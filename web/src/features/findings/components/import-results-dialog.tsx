'use client'

/**
 * Import results: upload a file another tool exported (Nessus, Qualys,
 * CycloneDX, SPDX, OSV, CSAF, OpenVEX, DefectDojo, or a ZIP of them). The
 * server detects the format; Preview parses and counts without writing,
 * Import ingests with the uploader's rights. Every value shown comes from the
 * uploaded file and is rendered as text.
 */

import { useState } from 'react'
import { toast } from 'sonner'
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
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

import {
  FindingImportError,
  importFindings,
  type FindingImportResponse,
  type ImportFileResponse,
} from '../api/finding-import-api'
import {
  formatLabel,
  importTotals,
  placeText,
  severityCounts,
  vexModeText,
} from '../lib/import-results'

const ACCEPT = '.nessus,.xml,.json,.zip,application/xml,text/xml,application/json,application/zip'

interface ImportResultsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Called after a successful import (not after a preview). */
  onImported?: () => void
}

export function ImportResultsDialog({ open, onOpenChange, onImported }: ImportResultsDialogProps) {
  const [file, setFile] = useState<File | null>(null)
  const [kb, setKb] = useState<File | null>(null)
  const [busy, setBusy] = useState<'preview' | 'import' | null>(null)
  const [preview, setPreview] = useState<FindingImportResponse | null>(null)
  const [result, setResult] = useState<FindingImportResponse | null>(null)
  const [error, setError] = useState<{ message: string; file?: ImportFileResponse } | null>(null)

  function reset() {
    setFile(null)
    setKb(null)
    setPreview(null)
    setResult(null)
    setError(null)
  }

  async function run(dryRun: boolean) {
    if (!file) return
    setBusy(dryRun ? 'preview' : 'import')
    setError(null)
    try {
      const resp = await importFindings({ file, knowledgeBase: kb, dryRun })
      if (dryRun) {
        setPreview(resp)
      } else {
        setResult(resp)
        const t = importTotals(resp.files ?? [])
        toast.success(`Imported ${t.created} new and ${t.updated} updated findings`)
        onImported?.()
      }
    } catch (e) {
      if (e instanceof FindingImportError) {
        setError({ message: e.message, file: e.file })
      } else {
        setError({ message: 'The import failed' })
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
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Import results</DialogTitle>
          <DialogDescription>
            Upload results another tool exported: Nessus, Qualys, SARIF, trivy, grype, semgrep,
            gitleaks, nuclei, ZAP, vuls, CycloneDX, SPDX, OSV, CSAF, OpenVEX or DefectDojo, or a ZIP
            of them. The format is detected from the file. Findings land only on assets you can
            change, and an import never resolves other findings.
          </DialogDescription>
        </DialogHeader>

        {!result && (
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="import-file">File</Label>
              <Input
                id="import-file"
                type="file"
                accept={ACCEPT}
                onChange={(e) => {
                  setFile(e.target.files?.[0] ?? null)
                  setPreview(null)
                  setError(null)
                }}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="import-kb">
                Qualys KnowledgeBase <span className="text-muted-foreground">(optional)</span>
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
                  Without the KnowledgeBase, Qualys detections keep their QID but have no title,
                  CVEs or CVSS.
                </p>
              )}
            </div>
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
              {shown.dry_run ? 'Preview: nothing was written. ' : ''}
              {vexModeText(shown.vex_mode, shown.vex_can_close)}
            </p>
            {(shown.files ?? []).map((f, i) => (
              <FileSummary key={`${f.name}-${i}`} file={f} dryRun={shown.dry_run ?? false} />
            ))}
          </div>
        )}

        <DialogFooter>
          {result ? (
            <Button onClick={() => onOpenChange(false)}>Close</Button>
          ) : (
            <>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={!file || busy !== null}
                onClick={() => run(true)}
              >
                {busy === 'preview' && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                Preview
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
                Import
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
            <Count label="Assets" value={stats?.assets ?? 0} />
            <Count label="Findings" value={stats?.findings ?? 0} />
            <Count label="Components" value={stats?.components ?? 0} />
            <Count label="VEX statements" value={stats?.statements ?? 0} />
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
          {(stats?.skipped ?? 0) > 0 && (
            <p className="text-muted-foreground text-xs">{stats?.skipped} records skipped.</p>
          )}
          {file.vex && (
            <p className="text-xs">
              VEX: {file.vex.matched} matching findings
              {dryRun
                ? `, ${file.vex.would_close} would be closed`
                : `, stored on ${file.vex.stored}, ${file.vex.closed} closed${file.vex.would_close ? `, ${file.vex.would_close} would be closed` : ''}`}
              {(file.vex.unmatchable ?? 0) > 0
                ? `; ${file.vex.unmatchable} statements cannot be matched (no package URL)`
                : ''}
            </p>
          )}
          {file.ingest && (
            <p className="text-xs">
              {file.ingest.findings_created} findings created, {file.ingest.findings_updated}{' '}
              updated, {file.ingest.assets_created} assets created
              {(file.ingest.assets_skipped_out_of_scope ?? 0) > 0
                ? `; ${file.ingest.assets_skipped_out_of_scope} hosts skipped (outside the assets you can change)`
                : ''}
            </p>
          )}
        </>
      )}
      {file.issues && file.issues.length > 0 && (
        <div>
          <p className="text-xs font-medium">{file.issues.length} problems</p>
          <IssueList issues={file.issues} />
        </div>
      )}
      {file.unmapped && file.unmapped.length > 0 && (
        <Collapsible>
          <CollapsibleTrigger className="text-muted-foreground text-xs underline">
            {file.unmapped.length} source fields not recognized
          </CollapsibleTrigger>
          <CollapsibleContent>
            <ul className="mt-1 max-h-32 overflow-y-auto font-mono text-[11px]">
              {file.unmapped.map((p) => (
                <li key={p} className="break-all">
                  {p}
                </li>
              ))}
            </ul>
          </CollapsibleContent>
        </Collapsible>
      )}
    </div>
  )
}
