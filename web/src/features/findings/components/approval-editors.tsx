'use client'

/**
 * Settings > Approvals, the editors: each row of the page opens one of these
 * in a dialog (a bottom sheet on a phone). An editor draws only its own
 * settings; the draft holds every setting, so a save sends the fields this
 * editor changed (and the whole policy when it changed). Saving rules are the
 * API's (finding_approval_settings_handler.go): settings:write, a recent
 * sign-in, lowering a level or relaxing the policy owner only and 24 hours
 * later, raising at once.
 */

import { useId } from 'react'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { FormField, FormSection, FormStack } from '@/features/shared/components/forms'
import type { FindingApprovalSettings, FPApprovalLevel } from '../api/use-findings-api'
import { kindLabel } from '../lib/approval-policy'
import {
  CapsFields,
  DeadlineFields,
  KindTierFields,
  MaterialAcceptedField,
  MaterialSinglePersonFPField,
  PoolFields,
  type PolicyDraft,
} from './approval-policy-form'
import {
  LevelSelector,
  clampPercent,
  levelDescription,
  levelsChanged,
  type LevelsDraft,
} from './finding-approval-settings-form'

type TFn = ReturnType<typeof useTranslation>['t']

/** The editors of the page, in the order of its rows. */
export const APPROVAL_EDITORS = [
  'false-positives',
  'accepted-risks',
  'suppression-rules',
  'approvers',
  'deadlines',
  'backup-contact',
] as const
export type ApprovalEditor = (typeof APPROVAL_EDITORS)[number]

/** A row's name (also the editor's title). */
export function editorTitle(t: TFn, editor: ApprovalEditor): string {
  switch (editor) {
    case 'false-positives':
      return t('findingApprovals.editor.falsePositives', 'False positives')
    case 'accepted-risks':
      return t('findingApprovals.editor.acceptedRisks', 'Accepted risks')
    case 'suppression-rules':
      return t('findingApprovals.editor.suppressionRules', 'Suppression rules')
    case 'approvers':
      return t('findingApprovals.editor.approvers', 'Approvers')
    case 'deadlines':
      return t('findingApprovals.editor.deadlines', 'Deadline and high risk')
    case 'backup-contact':
      return t('findingApprovals.settings.backupTitle', 'Backup contact')
  }
}

/** The editor's one-line description. */
export function editorDescription(t: TFn, editor: ApprovalEditor): string {
  switch (editor) {
    case 'false-positives':
      return levelDescription(t, 'fp')
    case 'accepted-risks':
      return levelDescription(t, 'accept')
    case 'suppression-rules':
      return t(
        'findingApprovals.editor.suppressionRulesDescription',
        'A rule decides many findings, future ones too, so it always needs another person. Only choices at or above the platform minimum are offered.'
      )
    case 'approvers':
      return t(
        'findingApprovals.editor.approversDescription',
        'Who may sign off a request, and when they sign in again.'
      )
    case 'deadlines':
      return t(
        'findingApprovals.editor.deadlinesDescription',
        'How long a request waits for a decision, and when a finding counts as high risk. Leave a field empty to use the platform value.'
      )
    case 'backup-contact':
      return t(
        'findingApprovals.settings.backupDescription',
        'An advisor or auditor outside the organization who is emailed whenever its only member approves their own finding request.'
      )
  }
}

export interface ApprovalEditorBodyProps {
  editor: ApprovalEditor
  settings: FindingApprovalSettings
  levels: LevelsDraft
  policy: PolicyDraft
  onLevels: (next: LevelsDraft) => void
  onPolicy: (next: PolicyDraft) => void
  canEdit: boolean
}

/** The fields of one editor. */
export function ApprovalEditorBody({
  editor,
  settings,
  levels,
  policy,
  onLevels,
  onPolicy,
  canEdit,
}: ApprovalEditorBodyProps) {
  const { t } = useTranslation()
  const id = useId()
  const disabled = !canEdit
  const changed = levelsChanged(levels, settings)
  const policyProps = { form: policy, onChange: onPolicy, disabled }
  const stricter = (
    <p className="text-cap text-muted-foreground">
      {t(
        'findingApprovals.editor.stricterHint',
        'Only choices at or above the platform minimum are offered. A relaxing change takes effect 24 hours after you save it; a stricter one at once.'
      )}
    </p>
  )

  switch (editor) {
    case 'false-positives': {
      const percentInForce = settings.second_look_percent ?? 0
      return (
        <FormStack>
          <LevelSelector
            kind="fp"
            value={levels.fpLevel}
            inForce={settings.fp_approval ?? 'all'}
            pending={settings.pending_fp_approval}
            pendingAt={settings.pending_fp_approval_at}
            changed={changed.fp}
            canEdit={canEdit}
            onChange={(v: FPApprovalLevel) => onLevels({ ...levels, fpLevel: v })}
          />
          <FormSection
            title={t('findingApprovals.editor.riskierTitle', 'Stricter for riskier findings')}
            description={t(
              'findingApprovals.policy.fpRowHint',
              'Default follows the false-positive level above; a tier here only raises it.'
            )}
          >
            <KindTierFields kind="false_positive" settings={settings} {...policyProps} />
            {stricter}
          </FormSection>
          <FormSection title={t('findingApprovals.editor.singleTitle', 'Decided by one person')}>
            <FormField
              id={`${id}-second-look`}
              label={t(
                'findingApprovals.fpLevel.secondLook',
                'Second look (% of single-person decisions)'
              )}
              required={false}
              hint={
                <span>
                  {t(
                    'findingApprovals.fpLevel.secondLookHelp',
                    'A random share of false positives decided by one person is flagged for another person to look at. 0 turns it off; at most 10.'
                  )}
                  {changed.percent && levels.percent < percentInForce && (
                    <>
                      {' '}
                      {t(
                        'findingApprovals.fpLevel.lowerPercentDelay',
                        'A lower second-look share takes effect 24 hours after you save it. A higher share takes effect at once.'
                      )}
                    </>
                  )}
                </span>
              }
            >
              {(control) => (
                <Input
                  {...control}
                  type="number"
                  min={0}
                  max={10}
                  step={1}
                  value={levels.percent}
                  disabled={disabled}
                  onChange={(e) =>
                    onLevels({ ...levels, percent: clampPercent(Number(e.target.value)) })
                  }
                  className="w-28"
                />
              )}
            </FormField>
            <MaterialSinglePersonFPField {...policyProps} />
          </FormSection>
        </FormStack>
      )
    }
    case 'accepted-risks':
      return (
        <FormStack>
          <LevelSelector
            kind="accept"
            value={levels.acceptLevel}
            inForce={settings.accept_approval ?? 'all'}
            pending={settings.pending_accept_approval}
            pendingAt={settings.pending_accept_approval_at}
            changed={changed.accept}
            canEdit={canEdit}
            onChange={(v: FPApprovalLevel) => onLevels({ ...levels, acceptLevel: v })}
          />
          <FormSection
            title={t('findingApprovals.editor.whoTitle', 'Who approves, by risk')}
            description={t(
              'findingApprovals.editor.acceptedTiersHint',
              'The approval an accepted risk needs when a second person approves it.'
            )}
          >
            <KindTierFields kind="accepted" settings={settings} {...policyProps} />
            {stricter}
          </FormSection>
          <CapsFields {...policyProps} />
          <MaterialAcceptedField {...policyProps} />
        </FormStack>
      )
    case 'suppression-rules':
      return (
        <FormStack>
          <FormSection title={kindLabel(t, 'rule_false_positive')}>
            <KindTierFields kind="rule_false_positive" settings={settings} {...policyProps} />
          </FormSection>
          <FormSection title={kindLabel(t, 'rule_accepted')}>
            <KindTierFields kind="rule_accepted" settings={settings} {...policyProps} />
          </FormSection>
          {stricter}
        </FormStack>
      )
    case 'approvers':
      return <PoolFields {...policyProps} />
    case 'deadlines':
      return <DeadlineFields {...policyProps} />
    case 'backup-contact':
      return (
        <FormStack>
          <FormField
            id={`${id}-email`}
            label={t('findingApprovals.settings.backupEmail', 'Email address')}
            optional
          >
            {(control) => (
              <Input
                {...control}
                type="email"
                maxLength={254}
                autoComplete="email"
                placeholder={t(
                  'findingApprovals.settings.backupPlaceholder',
                  'advisor@example.com'
                )}
                value={levels.email}
                disabled={disabled}
                onChange={(e) => onLevels({ ...levels, email: e.target.value })}
              />
            )}
          </FormField>
        </FormStack>
      )
  }
}
