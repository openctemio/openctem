'use client'

import { TonePill } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { formatLocalized, formatRelative } from '@/lib/format-date'

import type { ClosureEvidence as Evidence } from '../types'

const METHOD_LABEL: Record<string, string> = {
  covered_scan: 'Covered scan',
  retest: 'Retest',
  source_reported: 'Reported fixed by its source',
  obsolete_asset: 'Asset gone',
}

/**
 * Why the platform wants to close (or closed) a finding: the method and the
 * look behind it (tool, scan, when). Shared by Ready to close and Recently
 * auto-closed. Evidence values come from the scan record: plain text, capped.
 */
export function ClosureEvidence({
  method,
  evidence,
  at,
}: {
  method: string
  evidence: Evidence
  /** When the qualified look happened. */
  at?: string
}) {
  const { t, locale } = useTranslation()
  const tool = toDisplayText(String(evidence.tool ?? evidence.scanner ?? ''), 60)
  const scan = toDisplayText(String(evidence.command_id ?? evidence.scan_id ?? ''), 64)
  return (
    <div className="grid gap-1 text-sm">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-medium">
          {t(`findings.closureReview.method.${method}`, METHOD_LABEL[method] ?? method)}
        </span>
        {tool && <span className="text-muted-foreground">{tool}</span>}
        {evidence.held === true && (
          <TonePill
            tone="warning"
            label={t('findings.closureReview.held', 'Held for review')}
            title={t(
              'findings.closureReview.heldHint',
              'Many findings vanished in one scan, so nothing closed automatically.'
            )}
          />
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
        {at && (
          <span title={formatLocalized(at, locale, { time: true })}>
            {t('findings.closureReview.lookedAt', 'Scanned {when}', {
              when: formatRelative(at, '—', locale),
            })}
          </span>
        )}
        {scan && (
          <span className="font-mono" title={scan}>
            {t('findings.closureReview.scan', 'Scan {id}', { id: scan.slice(0, 8) })}
          </span>
        )}
      </div>
    </div>
  )
}
