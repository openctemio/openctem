'use client'

import { useState } from 'react'
import {
  CheckCircle2,
  CircleAlert,
  History,
  Loader2,
  Rocket,
  ScanEye,
  ShieldCheck,
} from 'lucide-react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  approveWorkflowVersion,
  invalidateWorkflowsCache,
  previewWorkflow,
  publishWorkflow,
  setWorkflowSimulate,
  validateWorkflow,
} from '@/lib/api/workflow-hooks'
import {
  WORKFLOW_PREVIEW_LIMITS,
  type CreateEdgeRequest,
  type CreateNodeRequest,
  type Workflow,
  type WorkflowPreviewResponse,
  type WorkflowValidateResponse,
} from '@/lib/api/workflow-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { useDisplayUser } from '@/hooks/use-display-user'
import { cn } from '@/lib/utils'
import {
  approvalState,
  errorCode,
  errorStatus,
  problemsFromError,
  publishRequirements,
} from '../lib/automation-lifecycle'
import { useAutomationLabels } from '../lib/use-automation-labels'
import { formatDay, usePersonName } from '../lib/use-person-name'
import { AutomationVersionsDialog } from './automation-versions-dialog'

type Draft = { nodes: CreateNodeRequest[]; edges: CreateEdgeRequest[] }

/** The "Before going live" checks: risk, what publishing needs, the latest validate. */
export function GoLiveChecks({
  workflow,
  validation,
  dirty,
}: {
  workflow: Workflow
  validation: WorkflowValidateResponse | null
  dirty: boolean
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const risk = workflow.risk_class ?? 'low'
  const needs = publishRequirements(risk)
  const ok = (text: string, key: string) => (
    <li key={key} className="flex gap-2" data-check={key}>
      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
      <span>{text}</span>
    </li>
  )
  const warn = (text: string, key: string) => (
    <li key={key} className="flex gap-2" data-check={key}>
      <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
      <span>{text}</span>
    </li>
  )
  const items: React.ReactNode[] = []
  items.push(
    (risk === 'low' ? ok : warn)(
      t('automations.golive.risk', 'Risk class: {risk}', { risk: labels.risk(risk) }),
      'risk'
    )
  )
  if (dirty) {
    items.push(
      warn(t('automations.golive.unsaved', 'Save the draft before going live.'), 'unsaved')
    )
  }
  if (validation) {
    items.push(
      validation.problems.length === 0
        ? ok(
            t('automations.golive.validated', 'Validated: no problems, {n} warnings', {
              n: validation.warnings.length,
            }),
            'validate'
          )
        : warn(
            t('automations.golive.problems', '{n} problems block going live', {
              n: validation.problems.length,
            }),
            'validate'
          )
    )
  }
  items.push(
    ok(
      t('automations.golive.needsPublish', 'Needs the publish permission for automations'),
      'publish'
    )
  )
  if (needs.stepUp) {
    items.push(
      warn(t('automations.golive.stepUp', 'Going live needs a fresh sign-in (step-up).'), 'stepup')
    )
  }
  if (needs.secondApprover) {
    items.push(
      warn(
        t(
          'automations.golive.secondApprover',
          'High risk: a second publisher approves this version before it goes live.'
        ),
        'approver'
      )
    )
  }
  if (typeof workflow.max_changes_per_run === 'number') {
    items.push(
      ok(
        t('automations.golive.cap', 'A run pauses after {n} changes.', {
          n: workflow.max_changes_per_run,
        }),
        'cap'
      )
    )
  }
  return (
    <ul className="space-y-2 text-sm" data-testid="golive-checks">
      {items}
    </ul>
  )
}

/**
 * The automation's lifecycle on the canvas header: simulate or live, the
 * published version, a pending approval, versions, validate, preview and
 * going live. Every action is gated in the UI by the permission it needs;
 * the API decides.
 */
export function AutomationLifecycleBar({
  workflow,
  dirty,
  getDraft,
  validation,
  onPreview,
  onValidate,
}: {
  workflow: Workflow
  /** The canvas has edits not yet saved. */
  dirty: boolean
  getDraft: () => Draft
  validation: WorkflowValidateResponse | null
  onPreview: (res: WorkflowPreviewResponse) => void
  onValidate: (res: WorkflowValidateResponse) => void
}) {
  const { t, locale } = useTranslation()
  const labels = useAutomationLabels()
  const person = usePersonName()
  const me = useDisplayUser()
  const canWrite = useHasPermission(Permission.AutomationsWrite)
  const canPublish = useHasPermission(Permission.AutomationsPublish)
  const [limit, setLimit] = useState<number>(WORKFLOW_PREVIEW_LIMITS[0])
  const [busy, setBusy] = useState<null | 'preview' | 'validate' | 'mode' | 'publish' | 'approve'>(
    null
  )
  const [goLiveOpen, setGoLiveOpen] = useState(false)
  const [versionsOpen, setVersionsOpen] = useState(false)
  const [publishProblems, setPublishProblems] = useState<string[] | null>(null)

  const mode = workflow.mode ?? 'simulate'
  const published = workflow.published_version ?? null
  const pending = workflow.pending_version ?? null
  const approval = approvalState(workflow, me?.id, canPublish)
  const canGoLive = mode === 'simulate' || !!workflow.draft_changed

  const rateLimited = (err: unknown) =>
    errorStatus(err) === 429 || errorCode(err) === 'RATE_LIMITED'

  const runPreview = async () => {
    setBusy('preview')
    try {
      onPreview(await previewWorkflow(workflow.id, { limit, ...getDraft() }))
    } catch (err) {
      toast.error(
        rateLimited(err)
          ? t(
              'automations.preview.rateLimited',
              'One preview every 10 seconds. Try again in a moment.'
            )
          : getErrorMessage(err, t('automations.preview.failed', 'Preview failed'))
      )
    } finally {
      setBusy(null)
    }
  }

  const runValidate = async (): Promise<WorkflowValidateResponse | null> => {
    setBusy('validate')
    try {
      const res = await validateWorkflow(workflow.id, getDraft())
      onValidate(res)
      return res
    } catch (err) {
      toast.error(
        rateLimited(err)
          ? t('automations.validate.rateLimited', 'Too many checks. Try again in a few seconds.')
          : getErrorMessage(err, t('automations.validate.failed', 'Check failed'))
      )
      return null
    } finally {
      setBusy(null)
    }
  }

  const switchToSimulate = async () => {
    setBusy('mode')
    try {
      await setWorkflowSimulate(workflow.id)
      toast.success(
        t('automations.mode.toSimulate', 'Switched to simulate. Nothing is changed or sent.')
      )
      await invalidateWorkflowsCache()
    } catch (err) {
      toast.error(getErrorMessage(err, t('automations.mode.failed', 'Could not change the mode')))
    } finally {
      setBusy(null)
    }
  }

  const openGoLive = () => {
    setPublishProblems(null)
    setGoLiveOpen(true)
    if (!dirty) void runValidate()
  }

  const publish = async () => {
    setBusy('publish')
    setPublishProblems(null)
    try {
      const res = await publishWorkflow(workflow.id)
      if ('status' in res && res.status === 'pending_approval') {
        toast.success(
          t(
            'automations.golive.pending',
            'Version {n} waits for a second publisher to approve it.',
            { n: res.version.version }
          )
        )
      } else {
        toast.success(t('automations.golive.live', 'The automation is live.'))
      }
      setGoLiveOpen(false)
      await invalidateWorkflowsCache()
    } catch (err) {
      const problems = problemsFromError(err)
      if (problems) {
        setPublishProblems(problems.map((p) => labels.issue(p.code, p.message)))
      } else {
        toast.error(getErrorMessage(err, t('automations.golive.failed', 'Could not go live')))
      }
    } finally {
      setBusy(null)
    }
  }

  const approve = async () => {
    if (!pending) return
    setBusy('approve')
    try {
      await approveWorkflowVersion(workflow.id, pending.id, pending.digest)
      toast.success(
        t('automations.approve.done', 'Version {n} approved; it is live.', { n: pending.version })
      )
      await invalidateWorkflowsCache()
    } catch (err) {
      const code = errorCode(err)
      toast.error(
        code === 'SELF_APPROVAL'
          ? t(
              'automations.approve.self',
              'You published this version; another person must approve it.'
            )
          : code === 'VERSION_CHANGED'
            ? t(
                'automations.approve.changed',
                'This version changed or is no longer waiting. Reload and review it again.'
              )
            : getErrorMessage(err, t('automations.approve.failed', 'Could not approve'))
      )
      await invalidateWorkflowsCache()
    } finally {
      setBusy(null)
    }
  }

  const spin = (what: typeof busy) =>
    busy === what ? <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" /> : null

  return (
    <div className="space-y-2 border-t px-4 py-3" data-testid="automation-lifecycle">
      <div className="flex flex-wrap items-center gap-2">
        <div
          role="group"
          aria-label={t('automations.mode.label', 'Mode')}
          className="inline-flex rounded-md border p-0.5"
        >
          <button
            type="button"
            aria-pressed={mode === 'simulate'}
            disabled={mode === 'simulate' || !canPublish || busy !== null}
            onClick={switchToSimulate}
            className={cn(
              'rounded px-3 py-1 text-sm',
              mode === 'simulate' ? 'bg-muted font-semibold' : 'text-muted-foreground'
            )}
          >
            {t('automations.mode.simulate', 'Simulate')}
          </button>
          <button
            type="button"
            aria-pressed={mode === 'live'}
            disabled={mode === 'live' || !canPublish || busy !== null}
            onClick={openGoLive}
            className={cn(
              'rounded px-3 py-1 text-sm',
              mode === 'live' ? 'bg-muted font-semibold' : 'text-muted-foreground'
            )}
          >
            {t('automations.mode.live', 'Live')}
          </button>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => void runValidate()}
          disabled={!canWrite || busy !== null}
        >
          {spin('validate') ?? <ShieldCheck className="h-4 w-4" />}
          {t('automations.validate.button', 'Validate')}
        </Button>

        <div className="inline-flex items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            onClick={runPreview}
            disabled={!canWrite || busy !== null}
          >
            {spin('preview') ?? <ScanEye className="h-4 w-4" />}
            {t('automations.preview.button', 'Preview')}
          </Button>
          <Select value={String(limit)} onValueChange={(v) => setLimit(Number(v))}>
            <SelectTrigger
              size="sm"
              className="w-[76px]"
              aria-label={t('automations.preview.limit', 'Subjects to preview')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {WORKFLOW_PREVIEW_LIMITS.map((n) => (
                <SelectItem key={n} value={String(n)}>
                  {n}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Button variant="outline" size="sm" onClick={() => setVersionsOpen(true)}>
          <History className="h-4 w-4" />
          {t('automations.version.list', 'Versions')}
        </Button>

        {canGoLive && (
          <Button
            size="sm"
            className="bg-brand text-white hover:bg-brand/90 dark:text-background"
            onClick={openGoLive}
            disabled={!canPublish || busy !== null}
            title={
              canPublish
                ? undefined
                : t('automations.golive.noPermission', 'Needs the publish permission')
            }
          >
            <Rocket className="h-4 w-4" />
            {mode === 'live'
              ? t('automations.golive.publishChanges', 'Publish changes')
              : t('automations.golive.button', 'Go live')}
          </Button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <span data-testid="version-line">
          {published
            ? t('automations.version.line', 'Version {n}, published by {who} on {date}', {
                n: published.version,
                who: person(published.published_by, published.published_by_name),
                date: formatDay(published.published_at, locale),
              })
            : t('automations.version.never', 'Never published')}
        </span>
        {published?.approved_by && (
          <span>
            {t('automations.version.approvedBy', 'approved by {who}', {
              who: person(published.approved_by, published.approved_by_name),
            })}
          </span>
        )}
        {workflow.draft_changed && (
          <Badge variant="outline" className="text-xs" data-testid="unpublished-changes">
            {t('automations.version.unpublished', 'Unpublished changes')}
          </Badge>
        )}
        {workflow.risk_class && (
          <span>
            {t('automations.golive.risk', 'Risk class: {risk}', {
              risk: labels.risk(workflow.risk_class),
            })}
          </span>
        )}
      </div>

      {pending && (
        <div
          className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-sm"
          data-testid="pending-version"
        >
          <span className="min-w-0 flex-1">
            {t(
              'automations.approve.waiting',
              'Version {n} waits for approval. Published by {who} on {date}.',
              {
                n: pending.version,
                who: person(pending.published_by, pending.published_by_name),
                date: formatDay(pending.created_at, locale),
              }
            )}{' '}
            {approval === 'self' &&
              t(
                'automations.approve.selfHint',
                'Another person with publish rights must approve it.'
              )}
          </span>
          {approval === 'can_approve' && (
            <Button size="sm" onClick={approve} disabled={busy !== null}>
              {spin('approve')}
              {t('automations.approve.button', 'Approve version {n}', { n: pending.version })}
            </Button>
          )}
        </div>
      )}

      {workflow.disabled_reason === 'uses_removed_type' && (
        <p className="rounded-md border border-warning/40 px-3 py-2 text-sm" role="status">
          {t(
            'automations.disabled.removedType',
            'Switched off: a step uses a type the platform no longer runs. Replace or remove the step marked "Removed type", then publish again.'
          )}
        </p>
      )}

      <Dialog open={goLiveOpen} onOpenChange={(o) => busy !== 'publish' && setGoLiveOpen(o)}>
        <DialogContent size="md">
          <DialogHeader>
            <DialogTitle>{t('automations.golive.title', 'Before going live')}</DialogTitle>
            <DialogDescription>
              {t(
                'automations.golive.description',
                'Live runs change findings and send messages for real. Check what publishing needs.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <GoLiveChecks workflow={workflow} validation={validation} dirty={dirty} />
            {publishProblems && (
              <ul
                className="mt-3 space-y-1 text-sm text-destructive"
                data-testid="publish-problems"
              >
                {publishProblems.map((p, i) => (
                  <li key={i}>{p}</li>
                ))}
              </ul>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGoLiveOpen(false)}>
              {t('automations.create.cancel', 'Cancel')}
            </Button>
            <Button
              className="bg-brand text-white hover:bg-brand/90 dark:text-background"
              onClick={publish}
              disabled={
                !canPublish ||
                dirty ||
                busy !== null ||
                (validation !== null && validation.problems.length > 0)
              }
            >
              {spin('publish')}
              {publishRequirements(workflow.risk_class).secondApprover
                ? t('automations.golive.submitForApproval', 'Publish for approval')
                : t('automations.golive.publish', 'Publish')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AutomationVersionsDialog
        workflow={workflow}
        open={versionsOpen}
        onOpenChange={setVersionsOpen}
      />
    </div>
  )
}
