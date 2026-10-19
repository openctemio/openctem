'use client'

/**
 * The conflict step of adding findings to a task: the findings that already
 * belong to another active task, where each one is, and a "Move here" choice
 * on those the caller may move. A task the caller cannot read shows as "a
 * task you cannot see", never by id.
 */

import { useTranslation } from '@/context/i18n-provider'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import type { FindingConflict } from '../api/types'
import { useOwnerNames } from '../api/use-owner-names'

export function ClaimConflictStep({
  conflicts,
  selected,
  onToggle,
  reason,
  onReason,
}: {
  conflicts: FindingConflict[]
  selected: ReadonlySet<string>
  onToggle: (findingId: string, on: boolean) => void
  reason: string
  onReason: (v: string) => void
}) {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  const n = conflicts.length
  const movable = conflicts.some((c) => c.can_move)
  return (
    <div className="space-y-3" data-testid="claim-conflict-step">
      <p className="text-sm">
        {t(`remediationClaim.conflict.intro.${n === 1 ? 'one' : 'other'}`, undefined, {
          count: n,
        })}
      </p>
      <ul className="divide-y rounded-md border" aria-label={t('remediationClaim.conflict.list')}>
        {conflicts.map((c) => {
          const owner =
            c.task_title === null
              ? null
              : [
                  owners.user(c.assignee_user_id ?? undefined),
                  owners.group(c.assignee_group_id ?? undefined),
                ]
                  .filter(Boolean)
                  .join(' · ') || t('remediationClaim.conflict.unassigned')
          const boxId = `move-${c.finding_id}`
          return (
            <li key={c.finding_id} className="flex items-start gap-3 p-3 text-sm">
              <div className="min-w-0 flex-1">
                <div className="truncate font-medium" title={c.finding_title}>
                  {c.finding_title || t('remediationClaim.conflict.untitled')}
                </div>
                <div className="text-muted-foreground text-xs">
                  {c.task_title === null
                    ? t('remediationClaim.conflict.hiddenTask')
                    : t('remediationClaim.conflict.inTask', undefined, {
                        task: c.task_title,
                        owner: owner ?? '',
                      })}
                </div>
              </div>
              {c.can_move && (
                <div className="flex shrink-0 items-center gap-2">
                  <Checkbox
                    id={boxId}
                    checked={selected.has(c.finding_id)}
                    onCheckedChange={(v) => onToggle(c.finding_id, v === true)}
                  />
                  <Label htmlFor={boxId} className="text-xs font-normal">
                    {t('remediationClaim.conflict.moveHere')}
                  </Label>
                </div>
              )}
            </li>
          )
        })}
      </ul>
      {movable ? (
        selected.size > 0 && (
          <div className="space-y-1.5">
            <Label htmlFor="claim-move-reason">{t('remediationClaim.conflict.reason')}</Label>
            <Textarea
              id="claim-move-reason"
              value={reason}
              maxLength={1000}
              placeholder={t('remediationClaim.conflict.reasonPlaceholder')}
              onChange={(e) => onReason(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">
              {t('remediationClaim.conflict.moveHint')}
            </p>
          </div>
        )
      ) : (
        <p className="text-muted-foreground text-xs">{t('remediationClaim.conflict.noMove')}</p>
      )}
    </div>
  )
}
