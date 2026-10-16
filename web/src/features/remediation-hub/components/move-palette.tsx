'use client'

/**
 * "Move to…": pick the task the selected findings go to, see the
 * compatibility hints (another fix, another owner, verification, emptying
 * this task) before confirming, or take the findings out of any task. The
 * server decides; the hints come from its preview.
 */

import { useEffect, useState } from 'react'
import { AlertTriangle, CornerDownLeft, Unlink } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import type { MoveWarning, RemediationTask } from '../api/types'
import { hubApi, useTasks } from '../api/use-remediation-hub'
import { TaskStatePill } from './task-bits'

export interface MoveTarget {
  task: RemediationTask | null
  warnings: MoveWarning[]
}

export function MovePalette({
  open,
  onOpenChange,
  source,
  findingIds,
  onConfirm,
  presetTarget,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  source: RemediationTask
  findingIds: string[]
  onConfirm: (target: MoveTarget) => void
  /** A target chosen by drag and drop: its preview runs right away. */
  presetTarget?: RemediationTask | null
}) {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [pending, setPending] = useState<MoveTarget | null>(null)
  const [checking, setChecking] = useState(false)
  const { data } = useTasks(
    {
      states: ['open', 'in_progress', 'verifying', 'on_hold'],
      search,
      sort: 'updated',
      perPage: 20,
    },
    open
  )
  const targets = (data?.data ?? []).filter((x) => x.id !== source.id)

  useEffect(() => {
    if (!open) {
      setPending(null)
      setSearch('')
    }
  }, [open])

  const choose = async (task: RemediationTask | null) => {
    setChecking(true)
    try {
      const preview = await hubApi.previewMove({
        from_task_id: source.id,
        from_version: source.version,
        finding_ids: findingIds,
        ...(task ? { to_task_id: task.id, to_version: task.version } : {}),
      })
      if (preview.warnings.length === 0) onConfirm({ task, warnings: [] })
      else setPending({ task, warnings: preview.warnings })
    } catch {
      setPending({ task, warnings: [] })
    } finally {
      setChecking(false)
    }
  }

  useEffect(() => {
    if (open && presetTarget) void choose(presetTarget)
    // Only when the palette opens with a dropped target.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, presetTarget])

  const hint = (task: RemediationTask) => {
    const out: string[] = []
    out.push(
      task.action_id === source.action_id
        ? t('remediationHub.move.sameFix')
        : t('remediationHub.move.differentFix')
    )
    if (
      (task.assignee_user_id ?? '') !== (source.assignee_user_id ?? '') ||
      (task.assignee_group_id ?? '') !== (source.assignee_group_id ?? '')
    )
      out.push(t('remediationHub.move.differentOwner'))
    return out.join(' · ')
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('remediationHub.move.title', undefined, { n: findingIds.length })}
      description={t('remediationHub.move.description')}
      filter={() => 1}
    >
      {pending ? (
        <div
          className="space-y-3 p-4"
          role="alertdialog"
          aria-label={t('remediationHub.move.confirmTitle')}
        >
          <p className="font-medium">
            {pending.task
              ? t('remediationHub.move.confirmTo', undefined, {
                  n: findingIds.length,
                  title: pending.task.title,
                })
              : t('remediationHub.move.confirmDetach', undefined, { n: findingIds.length })}
          </p>
          {pending.warnings.length > 0 && (
            <ul className="space-y-1 text-sm text-amber-700 dark:text-amber-400">
              {pending.warnings.map((w) => (
                <li key={w} className="flex items-center gap-2">
                  <AlertTriangle className="size-4 shrink-0" aria-hidden />
                  {t(`remediationHub.move.warning.${w}`)}
                </li>
              ))}
            </ul>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setPending(null)}>
              {t('remediationHub.actions.back')}
            </Button>
            <Button autoFocus onClick={() => onConfirm(pending)}>
              {t('remediationHub.move.confirm')}
            </Button>
          </div>
        </div>
      ) : (
        <>
          <CommandInput
            placeholder={t('remediationHub.move.search')}
            value={search}
            onValueChange={setSearch}
            disabled={checking}
          />
          <CommandList>
            <CommandEmpty>{t('remediationHub.move.none')}</CommandEmpty>
            <CommandGroup heading={t('remediationHub.move.tasks')}>
              {targets.map((task) => (
                <CommandItem key={task.id} value={task.id} onSelect={() => void choose(task)}>
                  <div className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate">{task.title}</span>
                    <span className="text-muted-foreground truncate text-xs">{hint(task)}</span>
                  </div>
                  <TaskStatePill state={task.state} />
                  <CornerDownLeft className="text-muted-foreground size-3.5" aria-hidden />
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandGroup heading={t('remediationHub.move.other')}>
              <CommandItem value="__detach__" onSelect={() => void choose(null)}>
                <Unlink className="size-4" aria-hidden />
                <span>{t('remediationHub.move.detach')}</span>
              </CommandItem>
            </CommandGroup>
          </CommandList>
        </>
      )}
    </CommandDialog>
  )
}
