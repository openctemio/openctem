'use client'

/** Triage actions and "create remediation task" of one alert. */

import { useMemo, useState } from 'react'
import { ListChecks, Loader2, MoreHorizontal, Radar } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission, useHasPermission } from '@/lib/permissions'
import { useIsMobile } from '@/hooks/use-mobile'
import { LazyScanAssetsDialog } from '@/features/scans/components/lazy-dialogs'
import type { ScanCandidate } from '@/features/scans/components/scan-assets-dialog'
import { createRemediationTask, setAlertState, useRevalidateEmergingThreats } from '../api'
import {
  MAX_TASK_TITLE_LENGTH,
  splitTaskable,
  taskTitle,
  type EmergingThreatDetail,
  type NotAffectedReason,
  type TargetState,
} from '../types'
import { NotAffectedDialog } from './not-affected-dialog'

export function AlertActions({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const revalidate = useRevalidateEmergingThreats()
  const isPhone = useIsMobile()
  const canTriage = useHasPermission(Permission.FindingsTriage)
  const canTask = useHasPermission(Permission.RemediationWrite)
  const canScanWrite = useHasPermission(Permission.ScansWrite)
  const canScanExecute = useHasPermission(Permission.ScansExecute)
  const canScan = canScanWrite && canScanExecute
  const [busy, setBusy] = useState(false)
  const [naOpen, setNaOpen] = useState(false)
  const [taskOpen, setTaskOpen] = useState(false)
  // A new key per opening: the dialog starts again from the alert's title.
  const [taskKey, setTaskKey] = useState(0)
  const [scanOpen, setScanOpen] = useState(false)
  const { eligible } = useMemo(() => splitTaskable(alert.assets), [alert.assets])
  const candidates = useMemo(() => scanCandidates(alert), [alert])
  const { state } = alert

  const move = async (
    target: TargetState,
    extra?: { reason: NotAffectedReason; note?: string }
  ) => {
    setBusy(true)
    try {
      await setAlertState(alert.id, target, extra)
      toast.success(t(`emergingThreats.toast.${target}`))
      setNaOpen(false)
      await revalidate()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const canAcknowledge = state === 'new'
  const canRemediate = state === 'new' || state === 'acknowledged'
  const canNotAffected = state === 'new' || state === 'acknowledged' || state === 'remediating'
  const canReopen = state !== 'new'

  // The state moves, in the order they are used. On a phone they and the
  // scan join one "More actions" menu beside the one main action (Create
  // remediation task), instead of five buttons on three rows.
  const moves: { id: string; label: string; run: () => void }[] = canTriage
    ? [
        ...(canAcknowledge
          ? [
              {
                id: 'acknowledge',
                label: t('emergingThreats.actions.acknowledge'),
                run: () => void move('acknowledged'),
              },
            ]
          : []),
        ...(canRemediate
          ? [
              {
                id: 'remediating',
                label: t('emergingThreats.actions.remediating'),
                run: () => void move('remediating'),
              },
            ]
          : []),
        ...(canNotAffected && alert.can_suppress
          ? [
              {
                id: 'not-affected',
                label: t('emergingThreats.actions.notAffected'),
                run: () => setNaOpen(true),
              },
            ]
          : []),
        ...(canReopen
          ? [
              {
                id: 'reopen',
                label: t('emergingThreats.actions.reopen'),
                run: () => void move('new'),
              },
            ]
          : []),
      ]
    : []

  const scanLabel = t('emergingThreats.scan.affected')
  const menuItems: ActionMenuEntry[] = [
    ...moves.map((m) => ({
      id: m.id,
      label: m.label,
      onSelect: m.run,
      disabledReason: busy ? t('emergingThreats.actions.busy') : undefined,
    })),
    ...(canScan
      ? [
          {
            id: 'scan',
            label: scanLabel,
            section: 'scan',
            onSelect: () => setScanOpen(true),
            disabledReason: candidates.length === 0 ? t('emergingThreats.scan.none') : undefined,
          },
        ]
      : []),
  ]

  return (
    <div className="flex flex-wrap items-center gap-2">
      {!isPhone &&
        moves.map((m) => (
          <Button key={m.id} size="sm" variant="outline" disabled={busy} onClick={m.run}>
            {m.label}
          </Button>
        ))}
      {canTask && (
        <Button
          size="sm"
          disabled={eligible.length === 0}
          title={eligible.length === 0 ? t('emergingThreats.task.nothingToAdd') : undefined}
          onClick={() => {
            setTaskKey((k) => k + 1)
            setTaskOpen(true)
          }}
        >
          <ListChecks className="me-2 h-4 w-4" aria-hidden />
          {t('emergingThreats.task.create')}
        </Button>
      )}
      {!isPhone && canScan && (
        <Button
          size="sm"
          variant="outline"
          disabled={candidates.length === 0}
          title={candidates.length === 0 ? t('emergingThreats.scan.none') : undefined}
          onClick={() => setScanOpen(true)}
        >
          <Radar className="me-2 h-4 w-4" aria-hidden />
          {scanLabel}
        </Button>
      )}
      {isPhone && menuItems.length > 0 && (
        <ActionMenu
          title={alert.vuln_id}
          label={t('emergingThreats.actions.menu', undefined, { vulnId: alert.vuln_id })}
          items={menuItems}
          trigger={
            <Button size="icon" variant="outline" aria-label={t('emergingThreats.actions.more')}>
              <MoreHorizontal className="h-4 w-4" aria-hidden />
            </Button>
          }
        />
      )}
      {canTask && (
        <CreateTaskDialog key={taskKey} alert={alert} open={taskOpen} onOpenChange={setTaskOpen} />
      )}
      {canScan && (
        <LazyScanAssetsDialog
          open={scanOpen}
          onOpenChange={setScanOpen}
          candidates={candidates}
          title={t('emergingThreats.scan.title', undefined, { vulnId: alert.vuln_id })}
        />
      )}
      <NotAffectedDialog
        open={naOpen}
        onOpenChange={setNaOpen}
        vulnId={alert.vuln_id}
        busy={busy}
        onConfirm={(reason, note) => void move('not_affected', { reason, note })}
      />
    </div>
  )
}

/** Why "Mark not affected" is missing, shown when the alert reaches beyond the caller's scope. */
export function OutOfScopeHint({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const eligibleState =
    alert.state === 'new' || alert.state === 'acknowledged' || alert.state === 'remediating'
  if (alert.can_suppress || !eligibleState) return null
  return (
    <Can permission={Permission.FindingsTriage}>
      <p className="text-xs text-muted-foreground">{t('emergingThreats.actions.outOfScopeHint')}</p>
    </Can>
  )
}

function CreateTaskDialog({
  alert,
  open,
  onOpenChange: setOpen,
}: {
  alert: EmergingThreatDetail
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const revalidate = useRevalidateEmergingThreats()
  const { eligible, alreadyInTask } = useMemo(() => splitTaskable(alert.assets), [alert.assets])
  const [title, setTitle] = useState(() => taskTitle(alert.vuln_id, alert.title))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [createdId, setCreatedId] = useState<string | null>(null)

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      const task = await createRemediationTask(
        title.trim(),
        eligible.map((a) => a.finding_id)
      )
      setCreatedId(task.id)
      await revalidate()
    } catch (err) {
      // 409: a finding joined another task since the page loaded.
      setError(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent size="md">
          <DialogHeader>
            <DialogTitle>{t('emergingThreats.task.title')}</DialogTitle>
            <DialogDescription>
              {t('emergingThreats.task.description', undefined, { n: eligible.length })}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            {createdId ? (
              <p className="text-sm">
                {t('emergingThreats.task.created')}{' '}
                <Link href={`/remediation/tasks/${createdId}`} className="underline">
                  {t('emergingThreats.task.open')}
                </Link>
              </p>
            ) : (
              <>
                <div className="space-y-1">
                  <Label htmlFor="et-task-title">{t('emergingThreats.task.titleLabel')}</Label>
                  <Input
                    id="et-task-title"
                    value={title}
                    maxLength={MAX_TASK_TITLE_LENGTH}
                    onChange={(e) => setTitle(e.target.value)}
                  />
                </div>
                {alreadyInTask.length > 0 && (
                  <p className="text-sm text-muted-foreground">
                    {t('emergingThreats.task.alreadyInTask', undefined, {
                      n: alreadyInTask.length,
                    })}
                  </p>
                )}
                {error && (
                  <p role="alert" className="text-sm text-destructive">
                    {error}
                  </p>
                )}
              </>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              {createdId ? t('emergingThreats.actions.close') : t('emergingThreats.actions.cancel')}
            </Button>
            {!createdId && (
              <Button
                disabled={busy || !title.trim() || eligible.length === 0}
                onClick={() => void submit()}
              >
                {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
                {t('emergingThreats.task.confirm', undefined, { n: eligible.length })}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

/** The count line shown on the detail next to the actions. */
export function TaskCoverageNote({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const { alreadyInTask } = useMemo(() => splitTaskable(alert.assets), [alert.assets])
  if (alreadyInTask.length === 0) return null
  return (
    <p className="text-xs text-muted-foreground">
      {t('emergingThreats.task.alreadyInTask', undefined, { n: alreadyInTask.length })}
    </p>
  )
}

/** Asset types a quick scan takes by name (the asset page's rule). */
const SCANNABLE_TYPES = new Set(['domain', 'subdomain', 'ip_address'])

/** The affected assets a quick scan can verify: domains, subdomains and IP addresses. */
export function scanCandidates(alert: Pick<EmergingThreatDetail, 'assets'>): ScanCandidate[] {
  const seen = new Set<string>()
  const out: ScanCandidate[] = []
  for (const a of alert.assets) {
    if (!SCANNABLE_TYPES.has(a.asset_type) || seen.has(a.asset_id)) continue
    seen.add(a.asset_id)
    out.push({ id: a.asset_id, label: a.asset_name, target: a.asset_name.trim() })
  }
  return out
}
