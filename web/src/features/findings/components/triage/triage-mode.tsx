'use client'

/**
 * Triage mode (`/findings/triage?<list query>`): the findings of one list
 * query, one at a time, decided from the keyboard. The default queue is
 * Needs triage (status new) in priority order.
 *
 * - The queue is read in windows through the findings list API, so the
 *   server applies the caller's tenant and data scope on every read.
 * - Each decision calls the per-finding endpoint the finding page calls,
 *   with the shown version as If-Match: a finding someone else changed is
 *   reloaded (412), never overwritten. False positive and risk acceptance
 *   stay approval requests decided by the organization's policy.
 * - Moving on costs one read (the finding), plus a window every 25.
 *
 * Design: research/234 §5.2 (D2).
 */

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useUrlParams, useUrlSettled } from '@/hooks/use-url-param'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared/components/error-state'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate } from '@/lib/permissions'
import { fetchTransitions, writeFindingAssignee, writeFindingStatus } from '../../api/triage-api'
import { useFindingApi } from '../../api/use-findings-api'
import { refreshFindingQuickViews } from '../../api/use-quick-views'
import type { TransitionDecision } from '../../api/use-finding-transitions'
import { useTriageSession } from '../../hooks/use-triage-session'
import { isFindingChanged } from '../../lib/finding-conflict'
import { isTriageLocked } from '../../lib/finding-detail'
import { firstReason } from '../../lib/transition-reasons'
import { triageActionFor, type TriageAction } from '../../lib/triage-keys'
import {
  TRIAGE_DEFAULT_QUERY,
  TRIAGE_LIST_PATH,
  changedElsewhere,
  clearSession,
  progress as progressOf,
  safeReturnPath,
  triageQuery,
} from '../../lib/triage-session'
import { FINDING_STATUS_CONFIG, requiresApproval, type FindingStatus } from '../../types'
import { ApprovalDialog } from '../approval-dialog'
import { AssigneeSelect, type AssigneeUser } from '../assignee-select'
import { LifecycleMoveDialog, type LifecycleMoveInput } from '../lifecycle/lifecycle-move-dialog'
import { TriageDecisionPanel } from './triage-decision-panel'
import { TriageFindingSkeleton, TriageFindingView } from './triage-finding-view'
import { TriageKeysDialog } from './triage-keys-dialog'
import { TriageQueuePanel } from './triage-queue-panel'
import { TriageTopBar } from './triage-top-bar'
import { Kbd } from './kbd'

type RequestTarget = 'false_positive' | 'accepted'

export function TriageMode() {
  const { t } = useTranslation()
  const router = useRouter()
  // Read only once the address bar holds this page's URL (see useUrlSettled).
  const params = useUrlParams()
  const settled = useUrlSettled()
  const search = params.toString()
  const query = useMemo(() => (settled ? triageQuery(search) : null), [settled, search])
  const { session, loadError, loadingWindow, direction, next, prev, go, decide, retry } =
    useTriageSession(query)

  const current =
    session && session.index < session.items.length ? session.items[session.index] : null
  const {
    data: loaded,
    error: findingError,
    mutate: reloadFinding,
  } = useFindingApi(current?.id ?? null, {
    // A finding that left the caller's scope answers 404: it is passed over
    // with a note below, not announced by the generic error toast.
    onError: () => {},
  })
  const shown = loaded && current && loaded.id === current.id ? loaded : null

  const [showEvidence, setShowEvidence] = useState(false)
  const [keysOpen, setKeysOpen] = useState(false)
  const [requestTarget, setRequestTarget] = useState<RequestTarget | null>(null)
  const [moveTarget, setMoveTarget] = useState<TransitionDecision | null>(null)
  const [busy, setBusy] = useState(false)
  const assignRef = useRef<HTMLDivElement>(null)
  const centreRef = useRef<HTMLDivElement>(null)
  const currentId = current?.id
  useEffect(() => {
    setShowEvidence(false)
    // After a decision, focus leaves the control that made it (the assignee
    // picker keeps focus on its trigger) for the next finding, so the keys
    // keep working and a screen reader reads the new finding.
    const active = typeof document === 'undefined' ? null : document.activeElement
    if (active && active.closest('[data-testid="triage-decision"]')) {
      centreRef.current?.focus({ preventScroll: true })
    }
  }, [currentId])

  const canConfirm = useCanMutate('PATCH /api/v1/findings/{id}/status')
  const canRequest = useCanMutate('POST /api/v1/findings/{id}/approvals')
  const canAssign = useCanMutate('POST /api/v1/findings/{id}/assign')
  const locked = shown ? isTriageLocked(shown.source) : false

  const outcome = current && session ? session.outcomes[current.id] : undefined
  const isChanged = !!(current && shown && changedElsewhere(current, shown, outcome))
  const gone =
    !!current &&
    findingError instanceof ApiClientError &&
    (findingError.statusCode === 404 || findingError.statusCode === 403)

  // A finding someone else changed since the queue loaded, or that left the
  // caller's scope, is passed over on the way forward with a note. On the way
  // back it stays on screen with the note.
  useEffect(() => {
    if (!current || outcome === 'changed' || direction.current !== 'forward') return
    if (isChanged && shown) {
      const cfg = FINDING_STATUS_CONFIG[shown.status]
      toast.info(
        t(
          'findings.triageMode.changedSkipped',
          'Changed by someone else (now {status}). Skipped.',
          {
            status: cfg ? t(cfg.labelKey, cfg.label) : shown.status,
          }
        )
      )
      decide(current.id, 'changed')
    } else if (gone) {
      toast.info(t('findings.triageMode.goneSkipped', 'No longer available to you. Skipped.'))
      decide(current.id, 'changed')
    }
  }, [current, outcome, isChanged, gone, shown, decide, direction, t])

  const reportWriteError = useCallback(
    (error: unknown, fallback: string) => {
      if (isFindingChanged(error)) {
        toast.info(
          t(
            'findings.conflict.changed',
            'Someone else changed this finding. It has been reloaded; check it and try again.'
          )
        )
        void reloadFinding()
        return
      }
      toast.error(getErrorMessage(error, fallback))
    },
    [reloadFinding, t]
  )

  const writeConfirm = useCallback(
    async (move: TransitionDecision, input?: LifecycleMoveInput) => {
      if (!shown) return
      setBusy(true)
      try {
        await writeFindingStatus(
          shown.id,
          {
            status: 'confirmed',
            ...(input?.note ? { resolution: input.note } : {}),
            ...(move.to_sub_status_id ? { sub_status_id: move.to_sub_status_id } : {}),
            ...(input?.fields ? { fields: input.fields } : {}),
          },
          shown.row_version
        )
        decide(shown.id, 'confirmed')
      } catch (error) {
        reportWriteError(error, t('findings.triage.statusFailed', 'Failed to update status'))
      } finally {
        setBusy(false)
      }
    },
    [shown, decide, reportWriteError, t]
  )

  // Every status decision asks the lifecycle first (the finding page's
  // status menu does the same): a blocked move shows its reason and writes
  // nothing. Returns the move, or undefined after saying why not.
  const allowedMove = useCallback(
    async (findingId: string, to: FindingStatus): Promise<TransitionDecision | undefined> => {
      setBusy(true)
      try {
        const moves = (await fetchTransitions(findingId)).transitions.filter((m) => m.to === to)
        const wantRequest = requiresApproval(to)
        const ok = (m: TransitionDecision) =>
          m.allowed && (wantRequest ? true : m.mode !== 'request')
        const move = moves.find((m) => ok(m) && !m.to_sub_status_id) ?? moves.find(ok)
        if (!move) {
          toast.error(
            firstReason(t, moves[0]?.blocked) ??
              t(
                'findings.triageMode.moveNotAllowed',
                "Not possible from this finding's current status."
              )
          )
        }
        return move
      } catch (error) {
        toast.error(
          getErrorMessage(error, t('findings.triage.statusFailed', 'Failed to update status'))
        )
        return undefined
      } finally {
        setBusy(false)
      }
    },
    [t]
  )

  const confirm = useCallback(async () => {
    if (!shown || busy || locked || !canConfirm) return
    const move = await allowedMove(shown.id, 'confirmed')
    if (!move) return
    // The organization's lifecycle asks a note or fields for this move.
    if ((move.note_min_len ?? 0) > 0 || (move.fields?.length ?? 0) > 0) {
      setMoveTarget(move)
      return
    }
    await writeConfirm(move)
  }, [shown, busy, locked, canConfirm, allowedMove, writeConfirm])

  // False positive and acceptance open the approval request only when the
  // lifecycle allows the move from the current status.
  const request = useCallback(
    async (to: RequestTarget) => {
      if (!shown || busy || locked || !canRequest) return
      if (await allowedMove(shown.id, to)) setRequestTarget(to)
    },
    [shown, busy, locked, canRequest, allowedMove]
  )

  const assign = useCallback(
    async (user: AssigneeUser | null) => {
      if (!shown) return
      if ((user?.id ?? null) === (shown.assigned_to ?? null)) return
      setBusy(true)
      try {
        await writeFindingAssignee(shown.id, user?.id ?? null, shown.row_version)
        if (user) decide(shown.id, 'assigned')
        else void reloadFinding()
      } catch (error) {
        reportWriteError(error, t('findings.triage.assignFailed', 'Failed to assign'))
      } finally {
        setBusy(false)
      }
    },
    [shown, decide, reloadFinding, reportWriteError, t]
  )

  const exit = useCallback(() => {
    void refreshFindingQuickViews()
    const fromList = session?.fromList === true
    const to = safeReturnPath(session?.returnTo ?? TRIAGE_LIST_PATH)
    clearSession()
    // Back in history restores the list with its filters and scroll.
    if (fromList && typeof window !== 'undefined' && window.history.length > 1) router.back()
    else router.push(to)
  }, [session, router])

  const onAction = useCallback(
    (action: TriageAction) => {
      switch (action) {
        case 'next':
          next()
          return
        case 'prev':
          prev()
          return
        case 'exit':
          exit()
          return
        case 'help':
          setKeysOpen(true)
          return
        case 'evidence':
          if (shown) setShowEvidence((v) => !v)
          return
        case 'openPage':
          if (current) router.push(`/findings/${encodeURIComponent(current.id)}`)
          return
        case 'skip':
          if (current && !busy) decide(current.id, 'skipped')
          return
        case 'confirm':
          void confirm()
          return
        case 'falsePositive':
          void request('false_positive')
          return
        case 'accept':
          void request('accepted')
          return
        case 'assign':
          if (shown && !locked && canAssign && !busy)
            assignRef.current?.querySelector<HTMLButtonElement>('button')?.click()
          return
      }
    },
    [next, prev, exit, shown, current, busy, locked, canAssign, confirm, request, decide, router]
  )

  // One listener for the page's life; it calls the latest handler.
  // Updated in the commit (not after paint): a key pressed right after the
  // next finding appears must act on that finding.
  const onActionRef = useRef(onAction)
  useLayoutEffect(() => {
    onActionRef.current = onAction
  })
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const action = triageActionFor(e)
      if (!action) return
      e.preventDefault()
      onActionRef.current(action)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  const queueLabel =
    query === TRIAGE_DEFAULT_QUERY
      ? t('findings.quickView.needs_triage', 'Needs triage')
      : t('findings.triageMode.thisView', 'Selected view')
  const progress = session ? progressOf(session) : null
  const done = !!session && session.exhausted && session.index >= session.items.length

  let centre: React.ReactNode
  if (loadError && (!session || session.items.length === 0)) {
    centre = (
      <ErrorState
        title={t('findings.triageMode.queueTitle', 'the triage queue')}
        error={loadError}
        onRetry={retry}
      />
    )
  } else if (!session || (!current && !done) || (current && !shown && !gone)) {
    centre = <TriageFindingSkeleton />
  } else if (done) {
    centre = (
      <div className="mx-auto max-w-md space-y-3 py-12 text-center" data-testid="triage-done">
        <h2 className="text-lg font-semibold">
          {session.items.length === 0
            ? t('findings.triageMode.emptyTitle', 'Nothing to triage here')
            : t('findings.triageMode.doneTitle', 'Queue done')}
        </h2>
        <p className="text-sm text-muted-foreground">
          {session.items.length === 0
            ? t('findings.triageMode.emptyBody', 'No finding in this view waits for a decision.')
            : t(
                'findings.triageMode.doneBody',
                '{decided} decided, {sent} sent for approval, {skipped} skipped.',
                {
                  decided: progress?.decided ?? 0,
                  sent: progress?.sentForApproval ?? 0,
                  skipped: progress?.skipped ?? 0,
                }
              )}
        </p>
        <Button onClick={exit}>{t('findings.triageMode.backToList', 'Back to the list')}</Button>
      </div>
    )
  } else if (gone) {
    centre = (
      <p className="py-12 text-center text-sm text-muted-foreground" role="note">
        {t('findings.triageMode.gone', 'This finding is no longer available to you.')}
      </p>
    )
  } else if (shown) {
    const note =
      isChanged || outcome === 'changed' ? (
        <p
          className="rounded-md border bg-muted/50 p-2 text-sm"
          role="note"
          data-testid="triage-changed"
        >
          {t(
            'findings.triageMode.changedNote',
            'Someone else changed this finding after the queue loaded. Check it before you decide.'
          )}
        </p>
      ) : undefined
    centre = <TriageFindingView finding={shown} showEvidence={showEvidence} note={note} />
  }

  const decisionState = {
    lockedReason: locked
      ? t(
          'findings.triageMode.locked',
          'Findings people reported are decided in their own workflow. Open the full page.'
        )
      : undefined,
    canConfirm,
    canRequest,
    canAssign,
    busy,
  }

  return (
    <Main fluid>
      <h1 className="sr-only">{t('findings.triageMode.pageTitle', 'Triage findings')}</h1>
      <div className="flex min-h-[calc(100dvh-8rem)] flex-col overflow-hidden rounded-lg border bg-background">
        {progress && (
          <TriageTopBar
            queueLabel={queueLabel}
            progress={progress}
            canPrev={!!session && session.index > 0}
            canNext={!!session && session.index < session.items.length}
            onPrev={prev}
            onNext={next}
            onExit={exit}
          />
        )}
        <div className="grid min-h-0 flex-1 lg:grid-cols-[17rem_minmax(0,1fr)_22rem]">
          {session && (
            <TriageQueuePanel
              session={session}
              onSelect={(i) => go(i, i < session.index ? 'back' : 'forward')}
            />
          )}
          <div
            ref={centreRef}
            tabIndex={-1}
            className="min-w-0 p-4 outline-none md:p-6"
            aria-busy={loadingWindow || undefined}
          >
            {!!loadError && !!session && session.items.length > 0 && (
              <p className="mb-3 text-sm text-destructive" role="alert">
                {t('findings.triageMode.windowFailed', 'The next findings could not be loaded.')}{' '}
                <button type="button" className="underline" onClick={retry}>
                  {t('common.retry', 'Retry')}
                </button>
              </p>
            )}
            {centre}
          </div>
          {!done && (
            <TriageDecisionPanel
              state={decisionState}
              onAction={onAction}
              assignControl={
                <div ref={assignRef}>
                  <AssigneeSelect
                    findingId={shown?.id}
                    value={
                      shown?.assigned_to && shown.assigned_to_user
                        ? {
                            id: shown.assigned_to,
                            name: shown.assigned_to_user.name,
                            email: shown.assigned_to_user.email,
                          }
                        : null
                    }
                    onChange={(u) => void assign(u)}
                    disabled={!shown || locked || !canAssign || busy}
                    placeholder={t('findings.triageMode.assignPlaceholder', 'Choose a person')}
                    size="sm"
                  />
                </div>
              }
            />
          )}
        </div>
        <div className="hidden flex-wrap items-center gap-4 border-t bg-card px-4 py-2 font-mono text-xs text-muted-foreground sm:flex">
          <span>
            <Kbd decorative={false}>?</Kbd> {t('findings.triageMode.action.help', 'All keys')}
          </span>
          <span>
            <Kbd decorative={false}>j</Kbd> <Kbd decorative={false}>k</Kbd>{' '}
            {t('findings.triageMode.footerMove', 'next and previous')}
          </span>
          <span>
            <Kbd decorative={false}>e</Kbd> {t('findings.triageMode.action.evidence', 'Evidence')}
          </span>
          <span>
            <Kbd decorative={false}>Enter</Kbd>{' '}
            {t('findings.triageMode.action.openPage', 'Full page')}
          </span>
        </div>
      </div>

      {shown && requestTarget && (
        <ApprovalDialog
          findingId={shown.id}
          targetStatus={requestTarget}
          maxAcceptanceDays={shown.max_acceptance_days}
          open
          onOpenChange={(open) => {
            if (!open) setRequestTarget(null)
          }}
          onSuccess={(result) => {
            const alone = result?.single_person === true
            decide(
              shown.id,
              requestTarget === 'false_positive'
                ? alone
                  ? 'fp_applied'
                  : 'fp_requested'
                : alone
                  ? 'accept_applied'
                  : 'accept_requested'
            )
          }}
        />
      )}
      {moveTarget && (
        <LifecycleMoveDialog
          open
          move={moveTarget}
          targetLabel={
            moveTarget.name ||
            t(FINDING_STATUS_CONFIG.confirmed.labelKey, FINDING_STATUS_CONFIG.confirmed.label)
          }
          noteRequired={false}
          onOpenChange={(open) => {
            if (!open) setMoveTarget(null)
          }}
          onConfirm={(input) => {
            const move = moveTarget
            setMoveTarget(null)
            void writeConfirm(move, input)
          }}
        />
      )}
      <TriageKeysDialog open={keysOpen} onOpenChange={setKeysOpen} />
    </Main>
  )
}
