'use client'

/**
 * "Stop using this source": the one dialog every page opens to retire an
 * import source (a sensor's tool, an uploaded tool, a connector), with safe
 * defaults (api docs/architecture/source-retirement.md).
 *
 * - The server previews what happens, with the same query it then runs:
 *   findings only this source reported are archived as source retired (not
 *   fixed, out of metrics and SLA, restorable); findings another source also
 *   reported stay as they are; findings in remediation and secrets stay open.
 * - Critical or known-exploited findings in the archive need their own tick.
 * - A reason is required (audit). Advanced options are folded: keep
 *   everything open, archive only some severities, include findings with a
 *   ticket, task or assignee.
 * - The API asks for re-authentication; the API client shows the prompt.
 * - A large source keeps archiving on the server; the retired sources list
 *   shows its progress.
 */

import { useId, useMemo, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Checkbox } from '@/components/ui/checkbox'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Label } from '@/components/ui/label'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { apiErrorMessage, toastError } from '@/lib/api/error-message'
import { formatCount } from '@/lib/format-metric'
import {
  isRetirementRunning,
  retireSource,
  useRetirePreview,
  type RetireOptions,
  type SourceSelector,
} from '../../api/source-retirement-api'

export const RETIRE_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
const MIN_REASON = 10
const MAX_REASON = 500

/** True when the reason has the length the API accepts. */
export function validRetireReason(reason: string): boolean {
  const n = [...reason.trim()].length
  return n >= MIN_REASON && n <= MAX_REASON
}

/** The options sent for the dialog's choices (empty = the defaults). */
export function retireOptionsOf(
  keepOpen: boolean,
  severities: readonly string[],
  includeEngaged: boolean
): RetireOptions {
  const out: RetireOptions = { mode: keepOpen ? 'keep_open' : 'archive' }
  if (!keepOpen && severities.length > 0 && severities.length < RETIRE_SEVERITIES.length) {
    out.severities = [...severities]
  }
  if (!keepOpen && includeEngaged) out.include_engaged = true
  return out
}

export interface RetireSourceDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  source: SourceSelector
  /** The name the page shows for the source (the server's label is used once known). */
  label?: string
  onRetired?: () => void
}

export function RetireSourceDialog({
  open,
  onOpenChange,
  source,
  label,
  onRetired,
}: RetireSourceDialogProps) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const reasonId = useId()
  const criticalId = useId()
  const keepOpenId = useId()
  const engagedId = useId()
  const [reason, setReason] = useState('')
  const [confirmCritical, setConfirmCritical] = useState(false)
  const [keepOpen, setKeepOpen] = useState(false)
  const [severities, setSeverities] = useState<string[]>([...RETIRE_SEVERITIES])
  const [includeEngaged, setIncludeEngaged] = useState(false)

  const options = useMemo(
    () => retireOptionsOf(keepOpen, severities, includeEngaged),
    [keepOpen, severities, includeEngaged]
  )
  const preview = useRetirePreview(open ? source : null, options)
  const p = preview.data?.preview
  const name = preview.data?.label || label || ''
  const needsCritical = !!p && p.critical_or_kev > 0
  const keptOpen = p
    ? p.kept_engaged + p.kept_in_progress + p.kept_secret + p.kept_severity_skipped
    : 0
  const ready = !!p && validRetireReason(reason) && (!needsCritical || confirmCritical)

  const reset = () => {
    setReason('')
    setConfirmCritical(false)
    setKeepOpen(false)
    setSeverities([...RETIRE_SEVERITIES])
    setIncludeEngaged(false)
  }

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset()
        onOpenChange(o)
      }}
      destructive
      title={t('findings.retireSource.title', 'Stop using {name}?', { name })}
      desc={t(
        'findings.retireSource.desc',
        'New data from this source is refused and recorded on each receipt. Findings only this source reported are archived as source retired: not fixed, out of metrics and SLA, and restored if you use the source again. Nothing is deleted.'
      )}
      confirmText={t('findings.retireSource.confirm', 'Stop using this source')}
      disabled={!ready}
      handleConfirm={async () => {
        try {
          const res = await retireSource({
            source,
            options,
            reason: reason.trim(),
            confirm_critical: confirmCritical,
          })
          const r = res.retirement
          if (isRetirementRunning(r)) {
            toast.success(
              t(
                'findings.retireSource.running',
                'Source stopped. Archiving {count} findings; the retired sources list shows the progress.',
                { count: n(r.planned_count) }
              )
            )
          } else {
            toast.success(
              r.already_retired
                ? t('findings.retireSource.already', 'This source was already stopped.')
                : t(
                    'findings.retireSource.done',
                    'Source stopped. {count} findings archived as source retired.',
                    { count: n(r.archived_count) }
                  )
            )
          }
          reset()
          onOpenChange(false)
          onRetired?.()
        } catch (e) {
          toastError(e, t('findings.retireSource.failed', 'Could not stop using the source'), t)
          void preview.mutate()
        }
      }}
    >
      <div className="space-y-3 text-sm">
        {preview.error ? (
          <p role="alert" className="text-destructive">
            {apiErrorMessage(
              preview.error,
              t('findings.retireSource.previewFailed', 'Could not count the findings'),
              t
            )}
          </p>
        ) : !p ? (
          <Skeleton className="h-20 w-full" />
        ) : (
          <section
            aria-label={t('findings.retireSource.previewLabel', 'What happens')}
            className="space-y-2 rounded-md border p-3"
            data-testid="retire-preview"
          >
            <p>
              {keepOpen
                ? t(
                    'findings.retireSource.keepOpenSummary',
                    'No finding is archived: only new data is refused.'
                  )
                : t(
                    'findings.retireSource.archiveSummary',
                    '{count} findings only this source reported will be archived as source retired.',
                    { count: n(p.archive) }
                  )}
            </p>
            {!keepOpen && p.archive > 0 && (
              <ul
                className="flex flex-wrap gap-2"
                aria-label={t('findings.retireSource.bySeverity', 'By severity')}
              >
                {RETIRE_SEVERITIES.filter((s) => (p.archive_by_severity[s] ?? 0) > 0).map((s) => (
                  <li key={s}>
                    <SeverityBadge severity={s} variant="soft">
                      {n(p.archive_by_severity[s] ?? 0)}
                    </SeverityBadge>
                  </li>
                ))}
              </ul>
            )}
            <p className="text-muted-foreground">
              {t(
                'findings.retireSource.corroborated',
                '{count} also reported by another source stay as they are.',
                { count: n(p.corroborated) }
              )}
            </p>
            {keptOpen > 0 && (
              <p className="text-muted-foreground">
                {t(
                  'findings.retireSource.keptOpen',
                  '{count} stay open: in remediation, with a ticket or assignee, secrets, or severities not chosen.',
                  { count: n(keptOpen) }
                )}
              </p>
            )}
            {!keepOpen && p.with_sla > 0 && (
              <p className="text-muted-foreground">
                {t('findings.retireSource.sla', '{count} of them leave their SLA.', {
                  count: n(p.with_sla),
                })}
              </p>
            )}
          </section>
        )}

        {needsCritical && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 p-3">
            <Checkbox
              id={criticalId}
              checked={confirmCritical}
              onCheckedChange={(v) => setConfirmCritical(v === true)}
            />
            <Label htmlFor={criticalId} className="font-normal leading-snug">
              {t(
                'findings.retireSource.confirmCritical',
                'I reviewed the {count} critical or known-exploited findings that will be archived.',
                { count: n(p?.critical_or_kev ?? 0) }
              )}
            </Label>
          </div>
        )}

        <div className="space-y-1.5">
          <Label htmlFor={reasonId}>
            {t('findings.retireSource.reason', 'Reason (recorded in the audit log)')}
          </Label>
          <Textarea
            id={reasonId}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={t(
              'findings.retireSource.reasonPlaceholder',
              'The scanner reports wrong results; we use the sensor scan instead.'
            )}
            maxLength={MAX_REASON}
            rows={3}
          />
          <p className="text-xs text-muted-foreground">
            {t('findings.retireSource.reasonLength', '10 to 500 characters.')}
          </p>
        </div>

        <Collapsible>
          <CollapsibleTrigger className="group inline-flex items-center gap-1 text-sm font-medium">
            <ChevronDown
              className="size-4 transition-transform group-data-[state=open]:rotate-180"
              aria-hidden
            />
            {t('findings.retireSource.advanced', 'Advanced options')}
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-2 space-y-3">
            <div className="flex items-start gap-2">
              <Checkbox
                id={keepOpenId}
                checked={keepOpen}
                onCheckedChange={(v) => setKeepOpen(v === true)}
              />
              <Label htmlFor={keepOpenId} className="font-normal leading-snug">
                {t(
                  'findings.retireSource.keepOpen',
                  'Keep every finding open; only refuse new data'
                )}
              </Label>
            </div>
            {!keepOpen && (
              <fieldset className="space-y-1.5">
                <legend className="text-sm">
                  {t('findings.retireSource.severities', 'Archive these severities')}
                </legend>
                <div className="flex flex-wrap gap-3">
                  {RETIRE_SEVERITIES.map((s) => {
                    const id = `${keepOpenId}-${s}`
                    return (
                      <div key={s} className="flex items-center gap-1.5">
                        <Checkbox
                          id={id}
                          checked={severities.includes(s)}
                          onCheckedChange={(v) =>
                            setSeverities((cur) =>
                              v === true ? [...cur, s] : cur.filter((x) => x !== s)
                            )
                          }
                        />
                        <Label htmlFor={id} className="font-normal">
                          <SeverityBadge severity={s} />
                        </Label>
                      </div>
                    )
                  })}
                </div>
              </fieldset>
            )}
            {!keepOpen && (
              <div className="flex items-start gap-2">
                <Checkbox
                  id={engagedId}
                  checked={includeEngaged}
                  onCheckedChange={(v) => setIncludeEngaged(v === true)}
                />
                <Label htmlFor={engagedId} className="font-normal leading-snug">
                  {t(
                    'findings.retireSource.includeEngaged',
                    'Also archive findings with a ticket, remediation task or assignee'
                  )}
                </Label>
              </div>
            )}
          </CollapsibleContent>
        </Collapsible>
      </div>
    </ConfirmDialog>
  )
}
