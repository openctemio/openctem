'use client'

/**
 * Actions on selected vulnerabilities, shared by the list's bulk bar and the
 * vulnerability page (api/docs/architecture/vulnerability-page.md, "Bulk
 * actions"). Each acts on the open findings of the selected CVEs that the
 * list's filters select, resolved by the API as the signed-in person:
 *   - Create remediation task: the task-from-query flow (a finding is in at
 *     most one active task; conflicts are shown, skipped or moved);
 *   - Request exception: one approval decision under the organization's
 *     policy (one or two approvers);
 *   - Retest: each finding the way its provenance allows (capped);
 *   - Export CSV: the findings behind the rows, with asset and title.
 */

import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import {
  GroupExceptionDialog,
  type GroupExceptionTarget,
} from '@/features/findings/components/group-exception-dialog'
import { CreateTaskFromQueryDialog } from '@/features/remediation-hub/components/create-task-from-query-dialog'
import { taskQueryApi } from '@/features/remediation-hub/api/use-task-query'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { vulnActionsApi, type VulnRetestResult, type VulnSelection } from '../../api/vuln-actions'

/** Findings filters a task query can carry (the list's own params are not findings filters). */
const TASK_FILTER_KEYS = ['severity', 'priority_class', 'source', 'asset_group_id']

/** The findings query of a selection: its CVEs, the list's findings filters, open only. */
export function selectionTaskParams(sel: VulnSelection): string {
  const from = new URLSearchParams(sel.params)
  const q = new URLSearchParams()
  for (const key of TASK_FILTER_KEYS) {
    const v = from.get(key)
    if (v) q.set(key, v)
  }
  q.set('cve_id', sel.cveIds.join(','))
  q.set('state', 'open')
  return q.toString()
}

export interface VulnActionAbilities {
  task: boolean
  exception: boolean
  retest: boolean
  export: boolean
}

type Translate = ReturnType<typeof useTranslation>['t']

/** "12 retests queued; 3 cannot be retested automatically; 5 wait for the limit". */
export function retestSummary(
  t: Translate,
  r: VulnRetestResult
): { title: string; detail: string } {
  const c = r.counts
  const parts: string[] = []
  if (c.in_flight)
    parts.push(
      t('vulnPage.actions.retest.inFlight', '{count} already running', { count: c.in_flight })
    )
  if (c.rate_limited)
    parts.push(
      t('vulnPage.actions.retest.rateLimited', '{count} wait for the retest limit', {
        count: c.rate_limited,
      })
    )
  if (c.not_eligible)
    parts.push(
      t('vulnPage.actions.retest.notEligible', '{count} cannot be retested automatically', {
        count: c.not_eligible,
      })
    )
  if (c.no_sensor)
    parts.push(
      t('vulnPage.actions.retest.noSensor', '{count} have no sensor online to retest them', {
        count: c.no_sensor,
      })
    )
  if (c.failed || c.not_found)
    parts.push(
      t('vulnPage.actions.retest.failed', '{count} could not be queued', {
        count: (c.failed ?? 0) + (c.not_found ?? 0),
      })
    )
  const rest = r.open_findings - r.attempted
  if (rest > 0)
    parts.push(
      t('vulnPage.actions.retest.notTried', '{count} not tried (at most 50 at a time)', {
        count: rest,
      })
    )
  return {
    title: t(
      'vulnPage.actions.retest.queued',
      '{count, plural, one {# retest queued} other {# retests queued}}',
      {
        count: c.queued ?? 0,
      }
    ),
    detail: parts.join('. '),
  }
}

/**
 * The actions the caller may run, and their dialogs. `onDone` runs after an
 * action changed something (refresh the list or the page).
 */
export function useVulnActions(onDone?: () => void) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const remediationEnabled = useModuleEnabled('remediation')
  const abilities: VulnActionAbilities = useMemo(
    () => ({
      task: remediationEnabled && can(Permission.RemediationWrite) && can(Permission.FindingsRead),
      exception: can(Permission.FindingsWrite),
      retest: can(Permission.FindingsVerify),
      export: can(Permission.FindingsExport),
    }),
    [can, remediationEnabled]
  )

  const [task, setTask] = useState<{ query: string; ignored: string[]; title: string } | null>(null)
  const [exception, setException] = useState<VulnSelection | null>(null)
  const [retest, setRetest] = useState<VulnSelection | null>(null)
  const [busy, setBusy] = useState(false)

  const createTask = useCallback(async (sel: VulnSelection, title: string) => {
    try {
      const q = await taskQueryApi.fromFilters(selectionTaskParams(sel))
      setTask({ ...q, title })
    } catch {
      setTask({ query: '', ignored: [], title })
    }
  }, [])

  const exportCsv = useCallback(
    async (params: URLSearchParams, cveIds?: string[]) => {
      setBusy(true)
      try {
        const res = await vulnActionsApi.exportCsv(params, cveIds)
        toast.success(t('vulnPage.actions.export.done', 'Export downloaded'), {
          description: res.filename,
        })
      } catch (err) {
        toast.error(
          getErrorMessage(
            err,
            t('vulnPage.actions.export.failed', 'Could not export the findings.')
          )
        )
      } finally {
        setBusy(false)
      }
    },
    [t]
  )

  const runRetest = useCallback(async () => {
    if (!retest) return
    try {
      const res = await vulnActionsApi.retest(retest)
      const s = retestSummary(t, res)
      if ((res.counts.queued ?? 0) > 0)
        toast.success(s.title, { description: s.detail || undefined })
      else toast.warning(s.title, { description: s.detail || undefined })
      setRetest(null)
      onDone?.()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('vulnPage.actions.retest.error', 'Could not queue the retests.'))
      )
    }
  }, [onDone, retest, t])

  const target: GroupExceptionTarget | undefined = useMemo(
    () =>
      exception
        ? {
            key: `${exception.cveIds.join(',')}?${exception.params}`,
            preview: (body) => vulnActionsApi.previewException(exception, body),
            request: (body) => vulnActionsApi.requestException(exception, body),
            description: t(
              'vulnPage.actions.exception.description',
              'One decision for the open findings of {cves} that you can see under the current filters. Findings found later are not covered.',
              {
                cves: exception.cveIds.length === 1 ? exception.cveIds[0] : exception.cveIds.length,
              }
            ),
            pendingText: t(
              'vulnPage.actions.exception.pending',
              'These findings already wait for an exception decision. Decide or cancel it first.'
            ),
          }
        : undefined,
    [exception, t]
  )

  const dialogs: ReactNode = (
    <>
      {task && (
        <CreateTaskFromQueryDialog
          open
          onOpenChange={(o) => {
            if (!o) {
              setTask(null)
              onDone?.()
            }
          }}
          initialQuery={task.query}
          initialTitle={task.title}
          ignoredFilters={task.ignored}
        />
      )}
      {target && (
        <GroupExceptionDialog
          target={target}
          open
          onOpenChange={(o) => !o && setException(null)}
          onCreated={() => onDone?.()}
        />
      )}
      <ConfirmDialog
        open={!!retest}
        onOpenChange={(o) => !o && setRetest(null)}
        title={t('vulnPage.actions.retest.title', 'Retest the open findings')}
        desc={t(
          'vulnPage.actions.retest.desc',
          'Re-checks the open findings of {count, plural, one {this vulnerability} other {# vulnerabilities}} that you can see, most urgent first, at most 50 at a time. Each finding is checked the way its source allows; findings found by people are not retested automatically.',
          { count: retest?.cveIds.length ?? 0 }
        )}
        confirmText={t('vulnPage.actions.retest.confirm', 'Retest')}
        handleConfirm={runRetest}
      />
    </>
  )

  return {
    abilities,
    busy,
    createTask,
    requestException: setException,
    retest: setRetest,
    exportCsv,
    dialogs,
  }
}
