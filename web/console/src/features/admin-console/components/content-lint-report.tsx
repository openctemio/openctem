'use client'

import type { ContentLintIssue, ContentLintReport } from '@/lib/api/generated'
import { useTranslation } from '@/context/i18n-provider'

function IssueList({
  title,
  issues,
  tone,
}: {
  title: string
  issues: ContentLintIssue[]
  tone: string
}) {
  if (issues.length === 0) return null
  return (
    <section className="space-y-1">
      <h4 className={`text-sm font-medium ${tone}`}>
        {title} <span className="tabular-nums">({issues.length})</span>
      </h4>
      <ul className="max-h-48 space-y-1 overflow-auto rounded-md border p-2 text-xs">
        {issues.map((i, n) => (
          <li key={`${i.path ?? ''}-${i.code}-${n}`} className="break-words">
            {i.path && <code className="me-1 text-muted-foreground">{i.path}</code>}
            <span className="font-mono">{i.code}</span>: {i.message}
          </li>
        ))}
      </ul>
    </section>
  )
}

/** Narrows an API error's details to a lint report. */
export function asLintReport(details: unknown): ContentLintReport | null {
  if (!details || typeof details !== 'object') return null
  const d = details as Record<string, unknown>
  const report = (d.lint ?? d) as Record<string, unknown>
  return typeof report.files === 'number' ||
    Array.isArray(report.errors) ||
    Array.isArray(report.secrets)
    ? (report as ContentLintReport)
    : null
}

/**
 * A pack's lint verdict: errors refuse it, warnings (each file left out is
 * one) and suspected secrets (path and kind only, never the value).
 */
export function ContentLintReportView({ report }: { report: ContentLintReport }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        {t('admin.cp.lintSummary', '{files} files, {items} items, tier {tier}.', {
          files: report.files ?? 0,
          items: report.items ?? 0,
          tier: report.tier ?? '-',
        })}
        {(report.excluded ?? 0) > 0 && (
          <span className="ms-1 font-medium text-warning">
            {t('admin.cp.excluded', '{count} file(s) left out because they failed lint.', {
              count: report.excluded ?? 0,
            })}
          </span>
        )}
      </p>
      <IssueList
        title={t('admin.cp.errors', 'Errors')}
        issues={report.errors ?? []}
        tone="text-destructive"
      />
      <IssueList
        title={t('admin.cp.secrets', 'Suspected secrets')}
        issues={report.secrets ?? []}
        tone="text-destructive"
      />
      <IssueList
        title={t('admin.cp.warnings', 'Warnings')}
        issues={report.warnings ?? []}
        tone="text-warning"
      />
      {report.truncated && (
        <p className="text-xs text-muted-foreground">
          {t('admin.cp.truncated', 'More findings were cut off (200 per list).')}
        </p>
      )}
    </div>
  )
}
