'use client'

/**
 * Finding evidence viewer: what the tool sent and what came back, per
 * detection and per retest attempt.
 *
 *   HTTP exchange · nuclei wordpress-click2shell · 3 min ago        [Copy curl]
 *   Request   GET https://h/wp-admin/js/theme.js                     [Raw | Parsed]
 *   Response  200 OK · 912 KB (truncated)
 *             …body with the matched part <mark>ed…
 *   Authorization: Bearer [secret: authorization #1  Reveal]
 *
 * Evidence is untrusted tool output: everything is React text (never HTML),
 * control and direction characters are shown as escapes, and the matched part
 * is a <mark>. Secret values arrive masked as «secret:kind#n»; Reveal (the
 * findings:evidence:reveal permission, a recent sign-in, audited server-side)
 * shows a value inline for 60 s, then masks it again. Revealed values live
 * only in this component's state.
 */

import * as React from 'react'
import { toast } from 'sonner'
import {
  ArrowDownLeft,
  ArrowUpRight,
  Check,
  Copy,
  Download,
  Eye,
  FileSearch,
  KeyRound,
  Lock,
  Terminal,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import { toDisplayBlock, toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import type { EvidenceItem } from '@/lib/api/generated'
import {
  revealEvidence,
  type FindingEvidenceItem,
  type RevealPurpose,
} from '../../api/use-finding-evidence-items'
import {
  bodyRanges,
  kindLabel,
  partMatched,
  placeholdersOf,
  rawRequestText,
  rawResponseText,
  segmentBody,
  splitPlaceholders,
  substitute,
  type Segment,
} from '../../lib/evidence-view'

/** How long a revealed value stays visible when the API gives no advice. */
const DEFAULT_MASK_AFTER_MS = 60_000

interface RevealState {
  values: Record<string, string>
  until: number
}

interface RevealContextValue {
  canReveal: boolean
  available: boolean
  revealable: Set<string>
  values: Record<string, string>
  reveal: (placeholders: string[], purpose: RevealPurpose) => Promise<Record<string, string> | null>
}

const RevealContext = React.createContext<RevealContextValue | null>(null)

function useReveal(): RevealContextValue {
  const ctx = React.useContext(RevealContext)
  if (!ctx) throw new Error('useReveal outside an evidence item')
  return ctx
}

export interface FindingEvidenceItemsProps {
  findingId: string
  items: FindingEvidenceItem[]
  className?: string
}

/** The list of evidence items of a finding (or of one retest attempt). */
export function FindingEvidenceItems({ findingId, items, className }: FindingEvidenceItemsProps) {
  if (items.length === 0) return null
  return (
    <div className={cn('space-y-4', className)} data-testid="finding-evidence-items">
      {items.map((it) => (
        <EvidenceItemCard key={it.id} findingId={findingId} record={it} />
      ))}
    </div>
  )
}

function EvidenceItemCard({
  findingId,
  record,
}: {
  findingId: string
  record: FindingEvidenceItem
}) {
  const canReveal = useHasPermission(Permission.EvidenceReveal)
  const [state, setState] = React.useState<RevealState>({ values: {}, until: 0 })
  const item = record.item as EvidenceItem

  // Re-mask when the reveal window ends, and never carry values to another item.
  React.useEffect(() => {
    if (!state.until) return
    const t = window.setTimeout(
      () => setState({ values: {}, until: 0 }),
      Math.max(0, state.until - Date.now())
    )
    return () => window.clearTimeout(t)
  }, [state.until])
  React.useEffect(() => setState({ values: {}, until: 0 }), [record.id])

  const reveal = React.useCallback(
    async (placeholders: string[], purpose: RevealPurpose) => {
      try {
        const values = await revealEvidence(findingId, record.id ?? '', placeholders, purpose)
        if (purpose === 'view') {
          setState((s) => ({
            values: { ...s.values, ...values },
            until: Date.now() + DEFAULT_MASK_AFTER_MS,
          }))
          toast.info('Value revealed for 60 seconds. This access is recorded in the audit log.')
        }
        return values
      } catch (err) {
        toast.error(getErrorMessage(err, 'Could not reveal the value'))
        return null
      }
    },
    [findingId, record.id]
  )

  const ctx = React.useMemo<RevealContextValue>(
    () => ({
      canReveal,
      available: record.secrets_available ?? false,
      revealable: new Set(record.revealable ?? []),
      values: state.values,
      reveal,
    }),
    [canReveal, record.secrets_available, record.revealable, state.values, reveal]
  )

  const label = item.label || [record.tool_name, record.rule_id].filter(Boolean).join(' ')
  return (
    <RevealContext.Provider value={ctx}>
      <section
        className="rounded-lg border bg-card"
        aria-label={`${kindLabel(record.kind ?? '')} evidence`}
        data-testid="evidence-item"
      >
        <header className="flex flex-wrap items-center gap-2 border-b px-4 py-2.5">
          <FileSearch className="h-4 w-4 text-muted-foreground" aria-hidden />
          <span className="text-sm font-medium">{kindLabel(record.kind ?? '')}</span>
          {label && (
            <span className="truncate text-xs text-muted-foreground">
              {toDisplayText(label, 200)}
            </span>
          )}
          {record.origin === 'retest' && (
            <Badge variant="outline" className="text-xs">
              Retest attempt
            </Badge>
          )}
          {record.truncated && (
            <Badge
              variant="outline"
              className="text-xs"
              title="The tool's output was longer than the stored part"
            >
              Truncated
            </Badge>
          )}
          <RelativeTime date={record.captured_at} className="ms-auto text-xs" />
          <ItemActions record={record} item={item} />
        </header>
        <div className="space-y-3 p-4">
          <ItemBody item={item} />
          <ItemFooter record={record} />
        </div>
      </section>
    </RevealContext.Provider>
  )
}

function ItemActions({ record, item }: { record: FindingEvidenceItem; item: EvidenceItem }) {
  const { canReveal, available, revealable, reveal } = useReveal()
  const curl = record.curl ?? (record.kind === 'curl' ? item.text : undefined)
  const curlSecrets = curl ? (curl.match(/«secret:[a-z_]{1,32}#[0-9]{1,4}»/g) ?? []) : []
  const canCopyWithSecrets =
    canReveal && available && curlSecrets.length > 0 && curlSecrets.every((p) => revealable.has(p))

  const copy = async (text: string, what: string) => {
    if (await copyToClipboard(text)) toast.success(`${what} copied`)
    else toast.error('Failed to copy to clipboard')
  }

  const copyCurlWithSecrets = async () => {
    if (!curl) return
    const values = await reveal([...new Set(curlSecrets)], 'copy_curl')
    if (!values) return
    await copy(substitute(curl, values, true), 'curl with secrets')
  }

  const download = () => {
    const text =
      record.kind === 'http_exchange'
        ? `${rawRequestText(item)}\n\n${rawResponseText(item)}`
        : JSON.stringify(item, null, 2)
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `evidence-${record.id}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex items-center gap-1">
      {curl && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs"
          onClick={() => void copy(curl, 'curl')}
          title="Copy a curl command that repeats the request (secret values stay masked)"
        >
          <Terminal className="me-1 h-3.5 w-3.5" aria-hidden />
          Copy curl
        </Button>
      )}
      {canCopyWithSecrets && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs"
          onClick={() => void copyCurlWithSecrets()}
          title="Copy the curl command with the real secret values (audited)"
        >
          <KeyRound className="me-1 h-3.5 w-3.5" aria-hidden />
          With secrets
        </Button>
      )}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-7 w-7 p-0"
        onClick={download}
        aria-label="Download the evidence (masked)"
        title="Download (masked)"
      >
        <Download className="h-3.5 w-3.5" aria-hidden />
      </Button>
    </div>
  )
}

function ItemBody({ item }: { item: EvidenceItem }) {
  switch (item.kind) {
    case 'http_exchange':
      return <HTTPExchangeView item={item} />
    case 'file_excerpt':
      return (
        <div className="space-y-1">
          {item.file?.path && (
            <p className="font-mono text-xs text-muted-foreground">
              {toDisplayText(item.file.path, 500)}
              {item.file.start_line ? `:${item.file.start_line}` : ''}
              {item.file.end_line && item.file.end_line !== item.file.start_line
                ? `-${item.file.end_line}`
                : ''}
            </p>
          )}
          <TextPane label="File excerpt" segments={splitPlaceholders(item.file?.snippet ?? '')} />
        </div>
      )
    case 'screenshot':
      return (
        <p className="text-sm text-muted-foreground">
          Screenshot{' '}
          {item.artifact?.media_type ? `(${toDisplayText(item.artifact.media_type, 100)})` : ''}
          {item.artifact?.sha256 ? ` · ${item.artifact.sha256.slice(0, 19)}…` : ''}
        </p>
      )
    default:
      return (
        <div className="space-y-1">
          {item.command && (
            <p className="font-mono text-xs text-muted-foreground">
              $ {toDisplayText(item.command, 500)}
              {typeof item.exit_code === 'number' ? ` (exit ${item.exit_code})` : ''}
            </p>
          )}
          <TextPane
            label={kindLabel(item.kind ?? '')}
            segments={splitPlaceholders(item.text ?? '')}
          />
        </div>
      )
  }
}

function HTTPExchangeView({ item }: { item: EvidenceItem }) {
  const q = item.http?.request
  const s = item.http?.response
  const [raw, setRaw] = React.useState(false)
  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <div className="inline-flex rounded-md border p-0.5 text-xs" role="group" aria-label="View">
          <button
            type="button"
            className={cn('rounded px-2 py-0.5', !raw && 'bg-muted font-medium')}
            aria-pressed={!raw}
            onClick={() => setRaw(false)}
          >
            Parsed
          </button>
          <button
            type="button"
            className={cn('rounded px-2 py-0.5', raw && 'bg-muted font-medium')}
            aria-pressed={raw}
            onClick={() => setRaw(true)}
          >
            Raw
          </button>
        </div>
      </div>
      {q && (
        <div className="space-y-1.5">
          <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase text-muted-foreground">
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
            Request
          </h4>
          {raw ? (
            <TextPane label="Raw request" segments={splitPlaceholders(rawRequestText(item))} />
          ) : (
            <>
              <p
                className={cn(
                  'break-all font-mono text-sm',
                  partMatched(item, 'request', 'url') && 'rounded bg-warning/20 px-1'
                )}
                dir="ltr"
              >
                <span className="font-semibold">{toDisplayText(q.method || 'GET', 16)}</span>{' '}
                <Segments segments={splitPlaceholders(q.url ?? '')} inline />
              </p>
              <Headers headers={q.headers} />
              {q.body && (
                <TextPane
                  label="Request body"
                  segments={segmentBody(q.body, bodyRanges(item, 'request'))}
                  note={q.body_truncated ? `truncated, ${q.body_size} bytes in all` : undefined}
                />
              )}
            </>
          )}
        </div>
      )}
      {s && (
        <div className="space-y-1.5">
          <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase text-muted-foreground">
            <ArrowDownLeft className="h-3.5 w-3.5" aria-hidden />
            Response
          </h4>
          {raw ? (
            <TextPane label="Raw response" segments={segmentBody(rawResponseText(item), [])} />
          ) : (
            <>
              <p className="font-mono text-sm">
                <span
                  className={cn(
                    partMatched(item, 'response', 'status') && 'rounded bg-warning/20 px-1'
                  )}
                >
                  {s.status ?? ''} {toDisplayText(s.reason ?? '', 128)}
                </span>
                {typeof s.time_ms === 'number' && s.time_ms > 0 && (
                  <span className="ms-2 text-xs text-muted-foreground">{s.time_ms} ms</span>
                )}
              </p>
              <Headers headers={s.headers} matched={partMatched(item, 'response', 'header')} />
              {s.body && (
                <TextPane
                  label="Response body"
                  segments={segmentBody(s.body, bodyRanges(item, 'response'))}
                  note={s.body_truncated ? `truncated, ${s.body_size} bytes in all` : undefined}
                />
              )}
            </>
          )}
        </div>
      )}
      {item.extracted && item.extracted.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Extracted:{' '}
          {item.extracted.map((v, i) => (
            <span key={i}>
              {i > 0 && ', '}
              <Segments segments={splitPlaceholders(v)} inline />
            </span>
          ))}
        </p>
      )}
    </div>
  )
}

function Headers({
  headers,
  matched,
}: {
  headers?: Array<{ name?: string; value?: string }>
  matched?: boolean
}) {
  if (!headers || headers.length === 0) return null
  return (
    <dl
      className={cn(
        'grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-3 gap-y-0.5 rounded-md border bg-muted/30 p-2 font-mono text-xs',
        matched && 'ring-1 ring-warning/50'
      )}
      dir="ltr"
    >
      {headers.map((h, i) => (
        <React.Fragment key={i}>
          <dt className="truncate text-muted-foreground">{toDisplayText(h.name ?? '', 256)}</dt>
          <dd className="break-all">
            <Segments segments={splitPlaceholders(h.value ?? '')} inline />
          </dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

function TextPane({
  label,
  segments,
  note,
}: {
  label: string
  segments: Segment[]
  note?: string
}) {
  return (
    <div>
      <pre
        aria-label={label}
        dir="ltr"
        tabIndex={0}
        data-testid="evidence-text"
        className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words [unicode-bidi:isolate] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Segments segments={segments} />
      </pre>
      {note && <p className="mt-1 text-xs text-muted-foreground">{note}</p>}
    </div>
  )
}

/** Renders segments as text, <mark> and secret chips. Never HTML. */
function Segments({ segments, inline }: { segments: Segment[]; inline?: boolean }) {
  return (
    <>
      {segments.map((seg, i) => {
        const content =
          seg.kind === 'text' ? (
            inline ? (
              toDisplayText(seg.text, 8192)
            ) : (
              toDisplayBlock(seg.text)
            )
          ) : (
            <SecretChip placeholder={seg.placeholder} />
          )
        return seg.mark ? (
          <mark
            key={i}
            className="rounded-sm bg-warning/30 text-foreground"
            data-testid="evidence-match"
          >
            {content}
          </mark>
        ) : (
          <React.Fragment key={i}>{content}</React.Fragment>
        )
      })}
    </>
  )
}

function SecretChip({ placeholder }: { placeholder: string }) {
  const { canReveal, available, revealable, values, reveal } = useReveal()
  const [copied, setCopied] = React.useState(false)
  const value = values[placeholder]
  const kind = placeholder.slice('«secret:'.length, placeholder.indexOf('#'))
  const n = placeholder.slice(placeholder.indexOf('#') + 1, -1)
  const revealableHere = canReveal && available && revealable.has(placeholder)

  if (value !== undefined) {
    const onCopy = async () => {
      const values = await reveal([placeholder], 'copy')
      if (values?.[placeholder] !== undefined && (await copyToClipboard(values[placeholder]))) {
        setCopied(true)
        window.setTimeout(() => setCopied(false), 1500)
      }
    }
    return (
      <span
        className="inline-flex items-center gap-1 rounded border border-warning/50 bg-warning/10 px-1 align-baseline"
        data-testid="evidence-secret-revealed"
      >
        <span className="break-all">{toDisplayText(value, 8192)}</span>
        <button
          type="button"
          onClick={() => void onCopy()}
          className="text-muted-foreground hover:text-foreground"
          aria-label={copied ? 'Copied' : `Copy ${kind} value`}
        >
          {copied ? (
            <Check className="h-3 w-3" aria-hidden />
          ) : (
            <Copy className="h-3 w-3" aria-hidden />
          )}
        </button>
      </span>
    )
  }
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-dashed px-1 align-baseline text-muted-foreground"
      data-testid="evidence-secret"
      title={
        revealableHere
          ? 'Masked secret value. Reveal shows it for 60 seconds; the access is audited.'
          : available
            ? 'Masked secret value. Revealing needs the Reveal Evidence Secrets permission.'
            : 'Masked secret value. It is no longer kept, so it cannot be revealed.'
      }
    >
      <Lock className="h-3 w-3" aria-hidden />
      <span>
        {kind} #{n}
      </span>
      {revealableHere && (
        <button
          type="button"
          onClick={() => void reveal([placeholder], 'view')}
          className="inline-flex items-center gap-0.5 font-medium text-foreground hover:underline"
          aria-label={`Reveal ${kind} #${n}`}
        >
          <Eye className="h-3 w-3" aria-hidden />
          Reveal
        </button>
      )}
    </span>
  )
}

function ItemFooter({ record }: { record: FindingEvidenceItem }) {
  const item = record.item as EvidenceItem
  const masked = placeholdersOf(item).length
  return (
    <p className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
      {record.tool_name && <span>Tool: {toDisplayText(record.tool_name, 100)}</span>}
      {record.rule_id && <span>Rule: {toDisplayText(record.rule_id, 200)}</span>}
      {record.template_digest && (
        <span title={record.template_digest}>Template {record.template_digest.slice(0, 19)}…</span>
      )}
      <span title={record.content_sha256}>
        Content {(record.content_sha256 ?? '').slice(0, 19)}…
      </span>
      {masked > 0 && (
        <span>
          {masked} masked value{masked > 1 ? 's' : ''}
          {!record.secrets_available && ' (no longer revealable)'}
        </span>
      )}
    </p>
  )
}
