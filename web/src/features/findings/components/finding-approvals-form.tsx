'use client'

/**
 * Settings > Approvals, the finding part: one row per approval type that says
 * what is set in plain words, each opening its editor in a dialog (a bottom
 * sheet on a phone). The page stays a short list; the detail is on demand.
 *
 * Every editor saves through `PATCH /api/v1/organization/settings/finding-
 * approvals`, a partial update (a field left out keeps its value; `policy`
 * replaces the whole policy): the level fields it changed, and `policy` when
 * the policy changed. The API applies them in one transaction, with one audit
 * entry and one notice to the approvers. It asks for a recent sign-in (the API
 * client re-authenticates), refuses a lowering or a relaxation by anyone but
 * an owner, and delays it 24 hours; refused, nothing is saved and the editor
 * keeps the draft and says why.
 */

import { useMemo, useState, type ReactNode } from 'react'
import { Clock } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useGroups } from '@/features/access-control/api/use-groups'
import { SettingsBlock, SettingsSection, SettingsSummaryRow } from '@/features/shared'
import { FormDialog } from '@/features/shared/components/forms'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateTime } from '@/lib/app-locale'
import { usePermissions, Permission } from '@/lib/permissions'
import {
  updateFindingApprovalSettings,
  type FindingApprovalSettings,
  type FindingApprovalSettingsUpdate,
} from '../api/use-findings-api'
import { POLICY_BOUNDS } from '../lib/approval-policy'
import {
  acceptedRiskSummary,
  approversSummary,
  deadlineSummary,
  falsePositiveSummary,
  suppressionRuleSummary,
} from '../lib/approval-summary'
import {
  ApprovalEditorBody,
  editorDescription,
  editorTitle,
  type ApprovalEditor,
} from './approval-editors'
import {
  TierGlossary,
  buildPolicy,
  parsePolicy,
  policyDirty,
  policyFromSettings,
  type PolicyDraft,
} from './approval-policy-form'
import {
  fpLevelText,
  acceptLevelText,
  levelsBody,
  levelsFromSettings,
  type LevelsDraft,
} from './finding-approval-settings-form'

type TFn = ReturnType<typeof useTranslation>['t']

/** The request body of an editor's save: only what changed; null when nothing did. */
export function editorSaveBody(
  levels: LevelsDraft,
  policy: PolicyDraft,
  settings: FindingApprovalSettings
): FindingApprovalSettingsUpdate | null {
  const levelFields = levelsBody(levels, settings)
  const policyChanged = policyDirty(policy, settings)
  if (!policyChanged && Object.keys(levelFields).length === 0) return null
  return {
    ...levelFields,
    ...(policyChanged ? { policy: buildPolicy(policy, settings) } : {}),
  }
}

/** What the toast says after a save: a waiting lowering, or saved at once. */
export function savedMessage(
  t: TFn,
  body: FindingApprovalSettingsUpdate,
  before: FindingApprovalSettings,
  next: FindingApprovalSettings | undefined
): string {
  const policyWaits =
    !!body.policy &&
    !!next?.pending_policy_at &&
    next.pending_policy_at !== before.pending_policy_at
  const levelWaits =
    (!!next?.pending_fp_approval && body.fp_approval !== undefined) ||
    (!!next?.pending_accept_approval && body.accept_approval !== undefined) ||
    (next?.pending_second_look_percent !== undefined && body.second_look_percent !== undefined)
  if (policyWaits)
    return t(
      'findingApprovals.policy.savedPending',
      'Saved. The relaxed rules take effect in 24 hours; until then the stricter rules apply. The approvers were told.'
    )
  if (levelWaits)
    return t(
      'findingApprovals.settings.savedPending',
      'Saved. The lower level takes effect in 24 hours; the approvers were told.'
    )
  return t('findingApprovals.settings.saved', 'Finding approval settings saved')
}

/** The lowerings that wait, one line each. */
export function waitingChanges(t: TFn, s: FindingApprovalSettings): string[] {
  const at = (v?: string) => (v ? formatDateTime(new Date(v)) : '')
  const lines: string[] = []
  if (s.pending_fp_approval)
    lines.push(
      t('findingApprovals.overview.waitingLevel', '{what}: "{level}" from {at}', {
        what: editorTitle(t, 'false-positives'),
        level: fpLevelText(t, s.pending_fp_approval).label,
        at: at(s.pending_fp_approval_at),
      })
    )
  if (s.pending_accept_approval)
    lines.push(
      t('findingApprovals.overview.waitingLevel', '{what}: "{level}" from {at}', {
        what: editorTitle(t, 'accepted-risks'),
        level: acceptLevelText(t, s.pending_accept_approval).label,
        at: at(s.pending_accept_approval_at),
      })
    )
  if (s.pending_second_look_percent !== undefined)
    lines.push(
      t('findingApprovals.overview.waitingPercent', 'Second look: {n} % from {at}', {
        n: String(s.pending_second_look_percent),
        at: at(s.pending_second_look_at),
      })
    )
  if (s.pending_policy)
    lines.push(
      t('findingApprovals.overview.waitingPolicy', 'Relaxed approval rules from {at}', {
        at: at(s.pending_policy_at),
      })
    )
  return lines
}

interface FindingApprovalsFormProps {
  settings: FindingApprovalSettings
  canEdit: boolean
  onSaved?: (next: FindingApprovalSettings) => void
  /** Rows drawn after the finding approval types (scan approval). */
  after?: ReactNode
}

export function FindingApprovalsForm({
  settings,
  canEdit,
  onSaved,
  after,
}: FindingApprovalsFormProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const savedLevels = useMemo(() => levelsFromSettings(settings), [settings])
  const savedPolicy = useMemo(() => policyFromSettings(settings), [settings])
  const [editor, setEditor] = useState<ApprovalEditor | null>(null)
  const [levels, setLevels] = useState(savedLevels)
  const [policy, setPolicy] = useState(savedPolicy)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [canceling, setCanceling] = useState(false)

  // The pool's name in its row: the groups are read only when a pool is set.
  const { groups } = useGroups(undefined, can(Permission.GroupsRead) && !!savedPolicy.groupId)
  const poolName = groups.find((g) => g.id === savedPolicy.groupId)?.name

  const open = (next: ApprovalEditor) => {
    setLevels(savedLevels)
    setPolicy(savedPolicy)
    setSaveError(null)
    setEditor(next)
  }

  const body = editor ? editorSaveBody(levels, policy, settings) : null
  const invalid = !!body?.policy && parsePolicy(policy).invalid

  const save = async () => {
    if (invalid) return
    if (!body) {
      setEditor(null)
      return
    }
    setSaving(true)
    setSaveError(null)
    try {
      const next = await updateFindingApprovalSettings(body)
      toast.success(savedMessage(t, body, settings, next))
      setEditor(null)
      onSaved?.(next)
    } catch (err) {
      setSaveError(
        getErrorMessage(
          err,
          t('findingApprovals.settings.saveFailed', 'Could not save the settings')
        )
      )
    } finally {
      setSaving(false)
    }
  }

  // The API drops every waiting lowering at once and keeps the values in force.
  const cancelPending = async () => {
    setCanceling(true)
    try {
      const next = await updateFindingApprovalSettings({ cancel_pending: true })
      toast.success(
        t('findingApprovals.settings.pendingCanceled', 'The waiting change was canceled')
      )
      onSaved?.(next)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('findingApprovals.settings.cancelFailed', 'Could not cancel the waiting change')
        )
      )
    } finally {
      setCanceling(false)
    }
  }

  const summaryInput = { cells: savedPolicy.cells, defaults: settings.defaults ?? {} }
  const { decideWithin, epss } = parsePolicy(savedPolicy)
  const waiting = waitingChanges(t, settings)
  const levelNote = (pending: boolean, at?: string) =>
    pending
      ? t('findingApprovals.overview.rowWaiting', 'A lower setting takes effect at {at}', {
          at: at ? formatDateTime(new Date(at)) : '',
        })
      : undefined
  // Each row: its editor, its name and the button that opens it ("Change",
  // or "View" without settings:write). The row's id stays a literal on the
  // element: settings search links to it (config/settings-nav.ts anchors).
  const row = (key: ApprovalEditor) => ({
    editor: key,
    label: editorTitle(t, key),
    actionLabel: canEdit
      ? t('findingApprovals.overview.change', 'Change')
      : t('findingApprovals.overview.view', 'View'),
    onAction: () => open(key),
  })

  return (
    <>
      <SettingsSection
        framed
        id="approval-levels"
        title={t('findingApprovals.policy.tiersTitle', 'Who approves')}
        description={t(
          'findingApprovals.overview.description',
          'Whoever decides, a reason is required and the decision is audited. Only an owner can lower a protection, and the lower setting takes effect 24 hours later.'
        )}
      >
        {waiting.length > 0 && (
          <SettingsBlock>
            <Alert data-testid="approval-policy-pending">
              <Clock className="h-4 w-4" aria-hidden />
              <AlertTitle>
                {t('findingApprovals.overview.waitingTitle', 'Lower protections are waiting')}
              </AlertTitle>
              <AlertDescription>
                <p>
                  {t(
                    'findingApprovals.overview.waitingBody',
                    'Until then the stricter settings apply.'
                  )}
                </p>
                <ul className="mt-1 list-disc ps-4">
                  {waiting.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </AlertDescription>
              {canEdit && (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="col-start-2 mt-2 justify-self-start"
                  disabled={canceling || saving}
                  onClick={() => void cancelPending()}
                >
                  {t('findingApprovals.overview.cancelWaiting', 'Cancel the waiting changes')}
                </Button>
              )}
            </Alert>
          </SettingsBlock>
        )}
        <SettingsSummaryRow
          id="false-positives"
          {...row('false-positives')}
          summary={falsePositiveSummary(t, savedLevels.fpLevel, summaryInput)}
          note={levelNote(
            !!settings.pending_fp_approval || settings.pending_second_look_percent !== undefined,
            settings.pending_fp_approval_at ?? settings.pending_second_look_at
          )}
        />
        <SettingsSummaryRow
          id="accepted-risks"
          {...row('accepted-risks')}
          summary={acceptedRiskSummary(t, savedLevels.acceptLevel, summaryInput)}
          note={levelNote(!!settings.pending_accept_approval, settings.pending_accept_approval_at)}
        />
        <SettingsSummaryRow
          id="suppression-rules"
          {...row('suppression-rules')}
          summary={suppressionRuleSummary(t, summaryInput)}
        />
        {after}
        <SettingsBlock>
          <TierGlossary />
        </SettingsBlock>
      </SettingsSection>
      <SettingsSection
        framed
        id="approval-rules"
        title={t('findingApprovals.overview.rulesTitle', 'For every request')}
      >
        <SettingsSummaryRow
          id="security-pool"
          {...row('approvers')}
          summary={approversSummary(t, {
            hasGroup: !!savedPolicy.groupId,
            groupName: poolName,
            strict: savedPolicy.strict,
            excludeAssignee: savedPolicy.excludeAssignee,
            stepUpAll: savedPolicy.stepUpAll,
          })}
        />
        <SettingsSummaryRow
          id="approval-limits"
          {...row('deadlines')}
          summary={deadlineSummary(
            t,
            decideWithin ?? POLICY_BOUNDS.decideWithinDays.max,
            epss ?? POLICY_BOUNDS.epss.max
          )}
        />
        <SettingsSummaryRow
          id="backup-contact"
          {...row('backup-contact')}
          summary={savedLevels.email || t('findingApprovals.overview.noBackup', 'Not set')}
        />
      </SettingsSection>
      {editor && (
        <FormDialog
          open
          onOpenChange={(o) => !o && setEditor(null)}
          title={editorTitle(t, editor)}
          description={editorDescription(t, editor)}
          size={
            editor === 'false-positives' ||
            editor === 'accepted-risks' ||
            editor === 'suppression-rules'
              ? 'lg'
              : 'md'
          }
          submitLabel={canEdit ? t('common.save', 'Save') : null}
          cancelLabel={canEdit ? undefined : t('common.close', 'Close')}
          onSubmit={() => void save()}
          submitting={saving}
          canSubmit={!invalid}
          dirty={canEdit && !!body}
          error={saveError}
          data-testid={`approval-editor-${editor}`}
        >
          <ApprovalEditorBody
            editor={editor}
            settings={settings}
            levels={levels}
            policy={policy}
            onLevels={setLevels}
            onPolicy={setPolicy}
            canEdit={canEdit}
          />
        </FormDialog>
      )}
    </>
  )
}
