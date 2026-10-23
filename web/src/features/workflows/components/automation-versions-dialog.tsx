'use client'

import { useState } from 'react'
import { RotateCcw } from 'lucide-react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  invalidateWorkflowsCache,
  rollbackWorkflowVersion,
  useWorkflowVersions,
} from '@/lib/api/workflow-hooks'
import type { Workflow, WorkflowVersion, WorkflowVersionStatus } from '@/lib/api/workflow-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { useAutomationLabels } from '../lib/use-automation-labels'
import { formatDay, usePersonName } from '../lib/use-person-name'

const STATUS: Record<WorkflowVersionStatus, [string, string]> = {
  published: ['automations.version.status.published', 'Live'],
  pending_approval: ['automations.version.status.pending_approval', 'Waiting for approval'],
  superseded: ['automations.version.status.superseded', 'Superseded'],
  retired: ['automations.version.status.retired', 'Retired'],
}

/** The versions of an automation, newest first, with rollback to an older one. */
export function AutomationVersionsDialog({
  workflow,
  open,
  onOpenChange,
}: {
  workflow: Workflow
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t, locale } = useTranslation()
  const labels = useAutomationLabels()
  const person = usePersonName()
  const canPublish = useHasPermission(Permission.AutomationsPublish)
  const { data, isLoading, mutate } = useWorkflowVersions(open ? workflow.id : null)
  const [target, setTarget] = useState<WorkflowVersion | null>(null)
  const [busy, setBusy] = useState(false)
  const items = data?.items ?? []

  const rollback = async (v: WorkflowVersion) => {
    setBusy(true)
    try {
      const res = await rollbackWorkflowVersion(workflow.id, v.id)
      toast.success(
        'status' in res && res.status === 'pending_approval'
          ? t(
              'automations.version.rollbackPending',
              'Version {n} republished; it waits for a second publisher.',
              { n: v.version }
            )
          : t('automations.version.rolledBack', 'Version {n} republished as the live version.', {
              n: v.version,
            })
      )
      setTarget(null)
      await Promise.all([mutate(), invalidateWorkflowsCache()])
    } catch (err) {
      toast.error(getErrorMessage(err, t('automations.version.rollbackFailed', 'Rollback failed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('automations.version.title', 'Versions')}</DialogTitle>
            <DialogDescription>
              {t(
                'automations.version.description',
                'Each publish keeps an unchangeable version. Rolling back republishes an older one as a new version, with the gate of its risk.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            {isLoading ? (
              <div className="space-y-2">
                {[1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : items.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t('automations.version.none', 'Not published yet.')}
              </p>
            ) : (
              <ol className="divide-y rounded-lg border" data-testid="versions-list">
                {items.map((v) => (
                  <li key={v.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                    <span className="font-medium tabular-nums">
                      {t('automations.version.number', 'Version {n}', { n: v.version })}
                    </span>
                    <Badge variant="outline" className="text-xs">
                      {STATUS[v.status] ? t(STATUS[v.status][0], STATUS[v.status][1]) : v.status}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {t('automations.golive.risk', 'Risk class: {risk}', {
                        risk: labels.risk(v.risk_class),
                      })}
                    </span>
                    <span className="w-full text-xs text-muted-foreground sm:w-auto sm:flex-1">
                      {v.published_at
                        ? t('automations.version.publishedBy', 'published by {who} on {date}', {
                            who: person(v.published_by, v.published_by_name),
                            date: formatDay(v.published_at, locale),
                          })
                        : t('automations.version.createdOn', 'created on {date}', {
                            date: formatDay(v.created_at, locale),
                          })}
                      {v.approved_by &&
                        ` · ${t('automations.version.approvedBy', 'approved by {who}', {
                          who: person(v.approved_by, v.approved_by_name),
                        })}`}
                    </span>
                    {v.status === 'superseded' && (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!canPublish || busy}
                        onClick={() => setTarget(v)}
                      >
                        <RotateCcw className="h-4 w-4" />
                        {t('automations.version.rollback', 'Roll back')}
                      </Button>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </DialogBody>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(o) => !o && !busy && setTarget(null)}
        title={t('automations.version.rollbackTitle', 'Roll back to version {n}?', {
          n: target?.version ?? '',
        })}
        desc={t(
          'automations.version.rollbackDesc',
          'Its steps become a new live version. Going back to a riskier version needs the same sign-in and approval as publishing it.'
        )}
        confirmText={t('automations.version.rollback', 'Roll back')}
        isLoading={busy}
        handleConfirm={() => (target ? rollback(target) : undefined)}
      />
    </>
  )
}
