'use client'

/**
 * Settings > Approvals, the finding part: the approval levels section and the
 * approval policy sections, saved by ONE save bar with ONE request.
 *
 * Both parts change `PATCH /api/v1/organization/settings/finding-approvals`,
 * a partial update (a field left out keeps its value; `policy` replaces the
 * whole policy). The body is the union of what each part sent on its own
 * before: the changed level fields, and `policy` when the policy changed. The
 * API applies them in one transaction, with one audit entry and one notice to
 * the approvers; refused (for example a relaxation by an administrator, which
 * is the owner's alone), nothing is saved and the draft is kept.
 */

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  updateFindingApprovalSettings,
  type FindingApprovalSettings,
  type FindingApprovalSettingsUpdate,
} from '../api/use-findings-api'
import {
  ApprovalLevelsSection,
  levelsBody,
  levelsChangeNames,
  levelsChanged,
  levelsFromSettings,
} from './finding-approval-settings-form'
import {
  ApprovalPolicySections,
  buildPolicy,
  parsePolicy,
  policyChangeNames,
  policyDirty,
  policyFromSettings,
} from './approval-policy-form'

interface FindingApprovalsFormProps {
  settings: FindingApprovalSettings
  canEdit: boolean
  onSaved?: (next: FindingApprovalSettings) => void
  /** Sections drawn after the finding sections, above the save bar. */
  after?: ReactNode
}

export function FindingApprovalsForm({
  settings,
  canEdit,
  onSaved,
  after,
}: FindingApprovalsFormProps) {
  const { t } = useTranslation()
  const savedLevels = useMemo(() => levelsFromSettings(settings), [settings])
  const savedPolicy = useMemo(() => policyFromSettings(settings), [settings])
  const [levels, setLevels] = useState(savedLevels)
  const [policy, setPolicy] = useState(savedPolicy)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState(false)

  // New saved values (a save, a canceled lowering, a reload) replace the draft.
  useEffect(() => setLevels(savedLevels), [savedLevels])
  useEffect(() => setPolicy(savedPolicy), [savedPolicy])

  const levelChange = levelsChanged(levels, settings)
  const levelsDirty = Object.values(levelChange).some(Boolean)
  const policyChanged = policyDirty(policy, settings)
  const dirty = levelsDirty || policyChanged
  const invalid = policyChanged && parsePolicy(policy).invalid
  const changes = [
    ...levelsChangeNames(t, levels, settings),
    ...policyChangeNames(t, policy, settings),
  ]

  const save = async () => {
    if (!dirty || invalid) return
    const body: FindingApprovalSettingsUpdate = {
      ...levelsBody(levels, settings),
      ...(policyChanged ? { policy: buildPolicy(policy, settings) } : {}),
    }
    setSaving(true)
    setSaveError(false)
    try {
      const next = await updateFindingApprovalSettings(body)
      const policyWaits =
        policyChanged &&
        !!next?.pending_policy_at &&
        next.pending_policy_at !== settings.pending_policy_at
      const levelWaits =
        (!!next?.pending_fp_approval && levelChange.fp) ||
        (!!next?.pending_accept_approval && levelChange.accept) ||
        (next?.pending_second_look_percent !== undefined && levelChange.percent)
      toast.success(
        policyWaits
          ? t(
              'findingApprovals.policy.savedPending',
              'Saved. The relaxed rules take effect in 24 hours; until then the stricter rules apply. The approvers were told.'
            )
          : levelWaits
            ? t(
                'findingApprovals.settings.savedPending',
                'Saved. The lower level takes effect in 24 hours; the approvers were told.'
              )
            : policyChanged && !levelsDirty
              ? t('findingApprovals.policy.saved', 'Approval policy saved')
              : t('findingApprovals.settings.saved', 'Finding approval settings saved')
      )
      onSaved?.(next)
    } catch (err) {
      setSaveError(true)
      toast.error(
        getErrorMessage(
          err,
          t('findingApprovals.settings.saveFailed', 'Could not save the settings')
        )
      )
    } finally {
      setSaving(false)
    }
  }

  const discard = () => {
    setLevels(savedLevels)
    setPolicy(savedPolicy)
    setSaveError(false)
  }

  return (
    <>
      <ApprovalLevelsSection
        settings={settings}
        draft={levels}
        onChange={setLevels}
        canEdit={canEdit}
        onSaved={onSaved}
      />
      <ApprovalPolicySections
        settings={settings}
        form={policy}
        onChange={setPolicy}
        canEdit={canEdit}
        saving={saving}
        onSaved={onSaved}
      />
      {after}
      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saving={saving}
          saveDisabled={invalid}
          changes={changes}
          error={
            saveError
              ? t('settings.saveBar.failed', "Couldn't save. Your changes are kept.")
              : undefined
          }
          onSave={() => void save()}
          onDiscard={discard}
        />
      )}
    </>
  )
}
