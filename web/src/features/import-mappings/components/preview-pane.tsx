'use client'

import { useEffect, useRef, useState } from 'react'
import { FileSearch, Loader2, TriangleAlert } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { PreviewError, previewMapping } from '../api/import-mappings-api'
import type { MappingDocument, PreviewResult } from '../types/import-mapping.types'

const DEBOUNCE_MS = 700

type PreviewState =
  | { status: 'idle' }
  | { status: 'loading'; last?: PreviewResult }
  | { status: 'ok'; result: PreviewResult }
  | { status: 'invalid'; errors: string[]; message: string }
  | { status: 'limited' }
  | { status: 'failed'; message: string }

interface PreviewPaneProps {
  document: MappingDocument
  file: File | null
  /** Previewing needs integrations:manage; without it the pane explains why it is empty. */
  canPreview: boolean
  onFields: (fields: string[]) => void
}

function recordLabel(record: Record<string, unknown>): string {
  for (const k of ['title', 'value', 'name']) {
    const v = record[k]
    if (typeof v === 'string' && v) return v
  }
  return ''
}

/** The CTIS records the draft makes from the sample, refreshed as the draft changes. */
export function PreviewPane({ document, file, canPreview, onFields }: PreviewPaneProps) {
  const { t } = useTranslation()
  const [state, setState] = useState<PreviewState>({ status: 'idle' })
  const docText = JSON.stringify(document)
  const tooLarge = t('importMappings.sample.tooLarge', 'The sample is larger than 5 MiB')
  const onFieldsRef = useRef(onFields)
  useEffect(() => {
    onFieldsRef.current = onFields
  }, [onFields])

  useEffect(() => {
    if (!canPreview || !file) {
      setState({ status: 'idle' })
      return
    }
    const ctrl = new AbortController()
    const timer = window.setTimeout(async () => {
      setState((s) => ({ status: 'loading', last: s.status === 'ok' ? s.result : undefined }))
      try {
        const result = await previewMapping(
          { document: JSON.parse(docText) as MappingDocument },
          file,
          ctrl.signal
        )
        if (ctrl.signal.aborted) return
        setState({ status: 'ok', result })
        onFieldsRef.current(result.fields ?? [])
      } catch (err) {
        if (ctrl.signal.aborted) return
        if (err instanceof PreviewError && err.status === 422) {
          setState({ status: 'invalid', errors: err.errors, message: err.message })
        } else if (err instanceof PreviewError && err.status === 413) {
          setState({ status: 'failed', message: tooLarge })
        } else if (err instanceof PreviewError && err.status === 429) {
          setState({ status: 'limited' })
        } else {
          setState({
            status: 'failed',
            message: err instanceof Error ? err.message : String(err),
          })
        }
      }
    }, DEBOUNCE_MS)
    return () => {
      window.clearTimeout(timer)
      ctrl.abort()
    }
  }, [docText, file, canPreview, tooLarge])

  if (!canPreview) {
    return (
      <p className="text-sm text-muted-foreground">
        {t(
          'importMappings.preview.noPermission',
          'Previewing a sample needs the permission to manage integrations.'
        )}
      </p>
    )
  }
  if (!file) {
    return (
      <div className="flex flex-col items-center gap-2 py-8 text-center text-sm text-muted-foreground">
        <FileSearch className="h-6 w-6" aria-hidden />
        {t(
          'importMappings.preview.noSample',
          'Choose a sample file to see the findings and assets this mapping makes from it.'
        )}
      </div>
    )
  }

  const result =
    state.status === 'ok' ? state.result : state.status === 'loading' ? state.last : undefined

  return (
    <div className="grid min-w-0 gap-3" aria-live="polite">
      {state.status === 'loading' && (
        <p className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
          {t('importMappings.preview.loading', 'Updating the preview…')}
        </p>
      )}
      {state.status === 'limited' && (
        <p className="rounded-md border p-3 text-sm" role="status">
          {t(
            'importMappings.preview.limited',
            'Too many previews in a short time. The preview updates again after your next change in a moment.'
          )}
        </p>
      )}
      {state.status === 'failed' && (
        <p
          className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm"
          role="alert"
        >
          {t('importMappings.preview.failed', 'The preview failed: {message}', {
            message: state.message,
          })}
        </p>
      )}
      {state.status === 'invalid' && (
        <div
          className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm"
          role="alert"
        >
          <p className="font-medium">
            {t('importMappings.preview.invalid', 'The mapping is not valid yet')}
          </p>
          <ul className="mt-1 list-disc ps-5">
            {(state.errors.length ? state.errors : [state.message]).map((e, i) => (
              <li key={i} className="break-words">
                {e}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result && <PreviewResultView result={result} />}
    </div>
  )
}

function PreviewResultView({ result }: { result: PreviewResult }) {
  const { t } = useTranslation()
  const collisions = result.warnings.filter((w) => w.code === 'identity_collision')
  const otherWarnings = result.warnings.filter((w) => w.code !== 'identity_collision')
  const s = result.stats

  return (
    <>
      <p className="text-sm">
        {t(
          'importMappings.preview.stats',
          '{records} records: {findings} findings, {assets} assets, {skipped} skipped.',
          { records: s.records, findings: s.findings, assets: s.assets, skipped: s.skipped }
        )}
        {s.truncated && (
          <span className="text-muted-foreground">
            {' '}
            {t('importMappings.preview.truncated', 'Only the first part of the sample was read.')}
          </span>
        )}
      </p>

      {collisions.length > 0 && (
        <div
          className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm"
          role="alert"
        >
          <p className="flex items-center gap-2 font-medium">
            <TriangleAlert className="h-4 w-4 text-destructive" aria-hidden />
            {t('importMappings.preview.collisionTitle', 'Different records get the same identity')}
          </p>
          <p className="mt-1 text-muted-foreground">
            {t(
              'importMappings.preview.collisionHelp',
              'They would be imported as one finding. Add an identity field that tells them apart, such as the location or the asset.'
            )}
          </p>
          <ul className="mt-1 list-disc ps-5">
            {collisions.map((w, i) => (
              <li key={i} className="break-words">
                {w.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      {otherWarnings.length > 0 && (
        <ul className="grid gap-1 text-sm">
          {otherWarnings.map((w, i) => (
            <li key={i} className="flex items-start gap-2 break-words">
              <TriangleAlert
                className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground"
                aria-hidden
              />
              {w.message}
            </li>
          ))}
        </ul>
      )}

      {result.unmapped.length > 0 && (
        <div className="grid gap-1">
          <p className="text-xs font-medium text-muted-foreground">
            {t('importMappings.preview.unmapped', 'Columns not used ({count})', {
              count: result.unmapped.length,
            })}
          </p>
          <div className="flex flex-wrap gap-1">
            {result.unmapped.map((f) => (
              <Badge
                key={f}
                variant="outline"
                className="max-w-full truncate font-mono text-xs font-normal"
              >
                {f}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {result.issues.length > 0 && (
        <details className="rounded-md border p-2 text-sm">
          <summary className="cursor-pointer font-medium">
            {t('importMappings.preview.issues', 'Records with problems: {count}', {
              count: result.issues.length,
            })}
          </summary>
          <ul className="mt-2 grid gap-1">
            {result.issues.map((iss, i) => (
              <li key={i} className="break-words text-muted-foreground">
                {t('importMappings.preview.issue', 'Record {record}, rule {rule}: {message}', {
                  record: iss.record,
                  rule: iss.rule + 1,
                  message: iss.message,
                })}
              </li>
            ))}
          </ul>
        </details>
      )}

      {result.items.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t('importMappings.preview.empty', 'The mapping makes nothing from this sample.')}
        </p>
      ) : (
        <ol className="grid gap-2">
          {result.items.map((item) => (
            <li key={`${item.kind}-${item.index}`} className="min-w-0 rounded-md border">
              <details>
                <summary className="flex cursor-pointer flex-wrap items-center gap-2 p-2 text-sm">
                  <Badge variant={item.kind === 'finding' ? 'secondary' : 'outline'}>
                    {item.kind === 'finding'
                      ? t('importMappings.kind.finding', 'Finding')
                      : t('importMappings.kind.asset', 'Asset')}
                  </Badge>
                  <span className="min-w-0 flex-1 truncate">
                    {recordLabel(item.record) ||
                      t('importMappings.preview.recordN', 'Record {n}', { n: item.index + 1 })}
                  </span>
                  {item.identity_key && (
                    <code
                      className="max-w-full truncate text-xs text-muted-foreground"
                      title={item.identity_key}
                    >
                      {item.identity_key}
                    </code>
                  )}
                </summary>
                <div className="grid gap-2 border-t p-2">
                  {Object.keys(item.identity ?? {}).length > 0 && (
                    <dl className="grid grid-cols-[minmax(0,auto)_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs">
                      {Object.entries(item.identity).map(([k, v]) => (
                        <div key={k} className="contents">
                          <dt className="font-mono text-muted-foreground">{k}</dt>
                          <dd className="break-all font-mono">{v}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                  <pre
                    className={cn(
                      'max-h-80 overflow-auto rounded bg-muted p-2 text-xs',
                      'whitespace-pre-wrap break-all'
                    )}
                  >
                    {JSON.stringify(item.record, null, 2)}
                  </pre>
                </div>
              </details>
            </li>
          ))}
        </ol>
      )}
    </>
  )
}
