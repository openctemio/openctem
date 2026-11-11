'use client'

/**
 * The sources the organization stopped using, with their progress and "Use
 * this source again" (which restores exactly the findings the retirement
 * archived; findings someone changed since stay as they are). Shown on the
 * import receipts page to holders of findings:sources:retire; hidden when
 * there are none or the API refuses (for example a narrowed data scope).
 */

import { useId, useState } from 'react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Progress } from '@/components/ui/progress'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { toastError } from '@/lib/api/error-message'
import { formatCount } from '@/lib/format-metric'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  isRetirementRunning,
  restoreSource,
  useSourceRetirements,
  type SourceRetirement,
} from '../../api/source-retirement-api'

type T = ReturnType<typeof useTranslation>['t']

/** The words of a retirement's state. */
export function retirementStateLabel(t: T, r: SourceRetirement): string {
  switch (r.state) {
    case 'applying':
      return t('findings.retiredSources.state.applying', 'Archiving')
    case 'restoring':
      return t('findings.retiredSources.state.restoring', 'Restoring')
    case 'restored':
      return t('findings.retiredSources.state.restored', 'In use again')
    default:
      return r.mode === 'keep_open'
        ? t('findings.retiredSources.state.blocked', 'Data refused, findings kept open')
        : t('findings.retiredSources.state.active', 'Stopped')
  }
}

function RestoreDialog({
  r,
  open,
  onOpenChange,
  onDone,
}: {
  r: SourceRetirement
  open: boolean
  onOpenChange: (o: boolean) => void
  onDone: () => void
}) {
  const { t, locale } = useTranslation()
  const reasonId = useId()
  const [reason, setReason] = useState('')
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (!o) setReason('')
        onOpenChange(o)
      }}
      title={t('findings.retiredSources.restoreTitle', 'Use {name} again?', { name: r.label })}
      desc={t(
        'findings.retiredSources.restoreDesc',
        'Its data is accepted again at once. The {count} findings it archived return to the status they had, except those someone changed since.',
        { count: formatCount(r.archived_count, locale) }
      )}
      confirmText={t('findings.retiredSources.restore', 'Use this source again')}
      handleConfirm={async () => {
        try {
          await restoreSource(r.id, reason.trim())
          toast.success(t('findings.retiredSources.restored', 'The source is in use again.'))
          setReason('')
          onOpenChange(false)
          onDone()
        } catch (e) {
          toastError(
            e,
            t('findings.retiredSources.restoreFailed', 'Could not use the source again'),
            t
          )
        }
      }}
    >
      <div className="space-y-1.5">
        <Label htmlFor={reasonId}>
          {t(
            'findings.retiredSources.restoreReason',
            'Reason (optional, recorded in the audit log)'
          )}
        </Label>
        <Textarea
          id={reasonId}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          maxLength={500}
          rows={2}
        />
      </div>
    </ConfirmDialog>
  )
}

function RetirementRow({ r, onChanged }: { r: SourceRetirement; onChanged: () => void }) {
  const { t, locale } = useTranslation()
  const n = (v: number) => formatCount(v, locale)
  const [open, setOpen] = useState(false)
  const running = isRetirementRunning(r)
  const done = r.state === 'restoring' ? r.restored_count + r.changed_count : r.archived_count
  return (
    <li className="space-y-1.5 py-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate font-medium" dir="auto">
            {r.label}
          </p>
          <p className="text-meta text-muted-foreground">
            {retirementStateLabel(t, r)} <RelativeTime date={r.retired_at} />
          </p>
        </div>
        {(r.state === 'active' || r.state === 'applying') && (
          <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
            {t('findings.retiredSources.restore', 'Use this source again')}
          </Button>
        )}
      </div>
      {running ? (
        <div aria-live="polite" className="space-y-1">
          <Progress
            value={r.planned_count > 0 ? Math.min(100, (done / r.planned_count) * 100) : 0}
          />
          <p className="text-meta text-muted-foreground">
            {t('findings.retiredSources.progress', '{done} of {total} findings', {
              done: n(done),
              total: n(r.planned_count),
            })}
          </p>
        </div>
      ) : (
        <p className="text-meta text-muted-foreground">
          {r.state === 'restored'
            ? t(
                'findings.retiredSources.restoredCounts',
                '{restored} findings restored, {changed} left as someone changed them',
                { restored: n(r.restored_count), changed: n(r.changed_count) }
              )
            : t(
                'findings.retiredSources.archivedCount',
                '{count} findings archived as source retired',
                {
                  count: n(r.archived_count),
                }
              )}
        </p>
      )}
      {open && <RestoreDialog r={r} open={open} onOpenChange={setOpen} onDone={onChanged} />}
    </li>
  )
}

export function RetiredSourcesSection() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const allowed = can(Permission.FindingsSourcesRetire)
  const { data, error, mutate } = useSourceRetirements(allowed)
  const items = data?.items ?? []
  if (!allowed || error || items.length === 0) return null
  return (
    <section className="rounded-lg border p-3" data-testid="retired-sources">
      <DetailSection
        title={t('findings.retiredSources.title', 'Sources you stopped using')}
        count={items.length}
      >
        <ul className="divide-y">
          {items.map((r) => (
            <RetirementRow key={r.id} r={r} onChanged={() => void mutate()} />
          ))}
        </ul>
        <Link
          href="/findings?retired_source_only=true"
          className="mt-2 inline-block text-sm text-primary hover:underline"
          data-testid="retired-only-link"
        >
          {t('findings.filter.field.retired_source_only', 'Only reported by a retired source')}
        </Link>
      </DetailSection>
    </section>
  )
}
