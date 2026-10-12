'use client'

import useSWR from 'swr'
import { useTranslation } from '@/context/i18n-provider'
import { enTranslate, type Translate } from '../lib/translate'
import { FileText, Loader2 } from 'lucide-react'

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogHeader,
  DialogBody,
} from '@/components/ui/dialog'
import { EmptyState, TonePill, type PillTone } from '@/features/shared'
import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type { RunTask, RunTaskLogLine, RunTaskLogs } from '@/lib/api/generated'
import { toDisplayBlock, toDisplayText } from '@/lib/untrusted-text'

/** The pill tone of a log level. */
export function logLevelTone(level?: string): PillTone {
  switch (level) {
    case 'error':
      return 'destructive'
    case 'warn':
      return 'warning'
    case 'debug':
      return 'muted'
    default:
      return 'info'
  }
}

/** What a refusal's message starts with ("refused by local policy: …", "refused by the managed policy: …"). */
const REFUSED_PREFIX = /^refused by\b/i

/**
 * The empty state of a task without log lines. A task that a policy refused
 * before any tool started, or that failed before it logged anything, says
 * why (its error message) instead of the generic "no logs".
 */
export function logsEmptyState(
  task?: Pick<RunTask, 'status' | 'error_message'> | null,
  t: Translate = enTranslate
): {
  title: string
  description: string
} {
  const msg = task?.error_message?.trim()
  if (msg && REFUSED_PREFIX.test(msg)) {
    return {
      title: t('scans.logs.refused'),
      description: toDisplayText(msg, 1024),
    }
  }
  if (msg && task?.status === 'failed') {
    return {
      title: t('scans.logs.failedEarly'),
      description: toDisplayText(msg, 1024),
    }
  }
  return {
    title: t('scans.logs.none'),
    description: t('scans.logs.noneHint'),
  }
}

/** A line's time as HH:MM:SS (UTC kept in the tooltip). */
function lineTime(ts?: string): string {
  if (!ts) return '-'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleTimeString(undefined, { hour12: false })
}

function LogLineRow({ line }: { line: RunTaskLogLine }) {
  const { t } = useTranslation()
  const fields = line.fields ? Object.entries(line.fields) : []
  return (
    <li className="border-b px-3 py-2 last:border-b-0" data-level={line.level}>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <time dateTime={line.ts} title={line.ts} className="tabular-nums">
          {lineTime(line.ts)}
        </time>
        <TonePill
          tone={logLevelTone(line.level)}
          label={t(`scans.logs.level.${line.level ?? 'info'}`, line.level)}
        />
        {line.source && <span className="font-mono">{toDisplayText(line.source, 64)}</span>}
      </div>
      {/* Sensor output: React text in a <pre>, never markup; hidden characters shown as escapes. */}
      <pre
        dir="ltr"
        className="mt-1 whitespace-pre-wrap break-words font-mono text-xs [unicode-bidi:isolate]"
      >
        {toDisplayBlock(line.msg ?? '')}
      </pre>
      {fields.length > 0 && (
        <details className="mt-1 text-xs">
          <summary className="cursor-pointer text-muted-foreground">
            {fields.length === 1
              ? t('scans.logs.fieldOne')
              : t('scans.logs.fieldMany', undefined, { count: fields.length })}
          </summary>
          <dl className="mt-1 grid grid-cols-[minmax(0,max-content)_1fr] gap-x-3 gap-y-0.5 font-mono">
            {fields.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{toDisplayText(k, 128)}</dt>
                <dd className="break-all">
                  {toDisplayText(typeof v === 'string' ? v : JSON.stringify(v))}
                </dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </li>
  )
}

/**
 * The log lines a task's sensor sent (RFC-029 §4.4.1), oldest first. The
 * platform cleaned and redacted them when it stored them; they are still
 * sensor output, so they are shown as plain text only.
 */
export function RunTaskLogsDialog({
  runId,
  taskId,
  tool,
  task,
  open,
  onOpenChange,
}: {
  runId: string
  taskId: string
  tool?: string
  /** The task's status and error: the empty state says why a refused or failed task has no logs. */
  task?: Pick<RunTask, 'status' | 'error_message'> | null
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useSWR<RunTaskLogs>(
    open ? scanRunEndpoints.taskLogs(runId, taskId) : null,
    (url: string) => get<RunTaskLogs>(url),
    { revalidateOnFocus: false }
  )
  const lines = data?.lines ?? []
  const empty = logsEmptyState(task, t)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>
            {tool
              ? t('scans.logs.titleTool', undefined, { tool: toDisplayText(tool, 64) })
              : t('scans.logs.title')}
          </DialogTitle>
          <DialogDescription>{t('scans.logs.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="p-0">
          {isLoading && (
            <div
              className="flex items-center gap-2 p-6 text-sm text-muted-foreground"
              aria-busy="true"
            >
              <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" />
              {t('scans.logs.loading')}
            </div>
          )}
          {error && !isLoading && (
            <p className="p-6 text-sm text-destructive">{t('scans.logs.loadFailed')}</p>
          )}
          {!isLoading && !error && lines.length === 0 && (
            <EmptyState
              icon={FileText}
              title={empty.title}
              description={empty.description}
              card={false}
            />
          )}
          {lines.length > 0 && (
            <ol aria-label={t('scans.logs.lines')} className="text-sm">
              {lines.map((l, i) => (
                <LogLineRow key={i} line={l} />
              ))}
            </ol>
          )}
          {data?.truncated && (
            <p className="border-t p-3 text-xs text-muted-foreground" role="note">
              {t('scans.logs.truncated')}
            </p>
          )}
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
