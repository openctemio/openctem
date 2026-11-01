'use client'

import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { safeInternalHref } from '@/lib/safe-href'

import type { RunMapNode } from '@/lib/api/generated'
import { TruncatedText } from '@/features/shared'

import { failureHelp, gapHelp, type CodeHelp } from '../lib/placement-help'
import { gapEdgeKind } from '../lib/edge-gap'
import { EdgeGapFixes } from './edge-gap-fixes'

/**
 * One code with what it means and where to fix it: the code (monospace, as
 * the API sent it), its class, the explanation, the fix and a link to the
 * page that applies it. Used for a step's error code and for each reason a
 * queued task waits.
 */
export function CodeHelpLine({ help, count }: { help: CodeHelp; count?: number }) {
  const { t } = useTranslation()
  const href = help.href ? safeInternalHref(help.href) : undefined
  return (
    <div className="space-y-0.5 text-xs" data-code={help.code}>
      <div className="flex flex-wrap items-center gap-1.5">
        <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">{help.code}</code>
        {help.classLabel && (
          <Badge variant="outline" className="px-1 py-0 text-[10px] font-normal">
            {help.classLabel}
          </Badge>
        )}
        {count !== undefined && (
          <span className="tabular-nums text-muted-foreground">
            {t('scans.placement.sensorCount', undefined, { count })}
          </span>
        )}
      </div>
      <p className="text-foreground">{help.text}</p>
      {help.fix && <p className="text-muted-foreground">{help.fix}</p>}
      {href && help.hrefLabel && (
        <Link href={href} className="font-medium text-primary underline-offset-4 hover:underline">
          {help.hrefLabel}
        </Link>
      )}
    </div>
  )
}

/** A same-origin fix link (the path is encoded before it reaches the DOM). */
function FixLink({ path, label }: { path: string; label: string }) {
  const fixHref = safeInternalHref(path)
  if (!fixHref) return null
  return (
    <Link href={fixHref} className="font-medium text-primary underline-offset-4 hover:underline">
      {label}
    </Link>
  )
}

/** A failed step's error code, explained, with its fix. */
export function StepFailureHelp({ code, errorClass }: { code?: string; errorClass?: string }) {
  const { t } = useTranslation()
  if (!code) return null
  return <CodeHelpLine help={failureHelp(code, errorClass, t)} />
}

/**
 * What a step did not do, from its structured outcome (never the English
 * summary): hosts not fully covered with the reason for each, and the
 * unfinished, unreachable and skipped counts. Hosts are scan targets,
 * shown as plain text.
 */
export function StepOutcome({ outcome }: { outcome?: RunMapNode['outcome'] }) {
  const { t } = useTranslation()
  if (!outcome) return null
  const gaps = outcome.coverage_gaps ?? []
  const gapTotal = Math.max(outcome.coverage_gap_count ?? 0, gaps.length)
  const counts: string[] = []
  if (outcome.unfinished_target_count) {
    counts.push(
      t('scans.step.outcome.unfinished', undefined, { count: outcome.unfinished_target_count })
    )
  }
  if (outcome.unreachable_target_count) {
    counts.push(
      t('scans.step.outcome.unreachable', undefined, { count: outcome.unreachable_target_count })
    )
  }
  if (outcome.skipped_target_count) {
    counts.push(t('scans.step.outcome.skipped', undefined, { count: outcome.skipped_target_count }))
  }
  if (gapTotal === 0 && counts.length === 0) return null
  return (
    <div className="space-y-1 text-xs" data-testid="step-outcome">
      {gapTotal > 0 && (
        <>
          <p className="font-medium text-foreground">
            {t('scans.step.outcome.gaps', undefined, { count: gapTotal })}
          </p>
          {gaps.length > 0 ? (
            <ul className="space-y-1">
              {gaps.map((g, i) => {
                const r = gapHelp(g, t)
                const fixKind = gapEdgeKind(g)
                return (
                  <li
                    key={`${g.host}-${i}`}
                    className="min-w-0"
                    data-gap-cause={g.cause || undefined}
                  >
                    <div className="flex min-w-0 items-baseline gap-2">
                      <TruncatedText value={g.host} className="min-w-0 font-mono" />
                      <span className="shrink-0 text-foreground">{r.label}</span>
                    </div>
                    {r.cert && <p className="text-foreground">{r.cert}</p>}
                    <p className="text-muted-foreground">{r.help}</p>
                    {fixKind ? (
                      <EdgeGapFixes kind={fixKind} />
                    ) : (
                      <>
                        {r.fix && <p className="text-muted-foreground">{r.fix}</p>}
                        {r.href && r.hrefLabel && <FixLink path={r.href} label={r.hrefLabel} />}
                      </>
                    )}
                  </li>
                )
              })}
            </ul>
          ) : (
            <p className="text-muted-foreground">{t('scans.step.outcome.seeTasks')}</p>
          )}
          {gapTotal > gaps.length && gaps.length > 0 && (
            <p className="text-muted-foreground">
              {t('scans.step.outcome.more', undefined, { count: gapTotal - gaps.length })}
            </p>
          )}
        </>
      )}
      {counts.map((line) => (
        <p key={line} className="text-muted-foreground">
          {line}
        </p>
      ))}
    </div>
  )
}
