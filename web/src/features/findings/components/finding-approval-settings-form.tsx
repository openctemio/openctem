'use client'

/**
 * Settings > Approvals, section "Approval policy": the organization's
 * approval levels for false positives and accepted risks, the second-look
 * share and the backup contact (server/docs/architecture/
 * finding-status-lifecycle.md, "Approval levels"). The page owns the draft
 * and its one save bar (`FindingApprovalsForm`); this section draws it.
 * Saving needs settings:write and a recent sign-in (the API client asks for
 * re-authentication); every change is audited and the approvers are told. A
 * lower level takes effect 24 hours later; a higher one at once.
 */

import { useId, useState } from 'react'
import { AlertTriangle, Clock } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { SettingsBlock, SettingsRow, SettingsSection } from '@/features/shared'
import {
  updateFindingApprovalSettings,
  type FindingApprovalSettings,
  type FindingApprovalSettingsUpdate,
  type FPApprovalLevel,
} from '../api/use-findings-api'

type TFn = ReturnType<typeof useTranslation>['t']

/** What a level decides: a false positive or an accepted risk. */
export type ApprovalLevelKind = 'fp' | 'accept'

const LEVELS: FPApprovalLevel[] = ['all', 'high_and_above', 'off']

/** The false-positive level's label and explanation. */
export function fpLevelText(t: TFn, level: FPApprovalLevel): { label: string; help: string } {
  switch (level) {
    case 'high_and_above':
      return {
        label: t('findingApprovals.fpLevel.high_and_above', 'Only for serious findings'),
        help: t(
          'findingApprovals.fpLevel.high_and_aboveHelp',
          'A second person approves a false positive on a critical or high finding, a known exploited vulnerability (KEV), P0 or P1, a validated exploit, or a crown-jewel or internet-exposed asset. Anyone with approval permission may decide the others alone.'
        ),
      }
    case 'off':
      return {
        label: t('findingApprovals.fpLevel.off', 'Never'),
        help: t(
          'findingApprovals.fpLevel.offHelp',
          'Anyone with approval permission may mark any finding a false positive alone.'
        ),
      }
    default:
      return {
        label: t('findingApprovals.fpLevel.all', 'Always (recommended)'),
        help: t(
          'findingApprovals.fpLevel.allHelp',
          'Every false positive needs a second person to approve it.'
        ),
      }
  }
}

/** The risk acceptance level's label and explanation. */
export function acceptLevelText(t: TFn, level: FPApprovalLevel): { label: string; help: string } {
  switch (level) {
    case 'high_and_above':
      return {
        label: t('findingApprovals.acceptLevel.high_and_above', 'Only for serious findings'),
        help: t(
          'findingApprovals.acceptLevel.high_and_aboveHelp',
          'A second person approves accepting the risk of a critical or high finding, a known exploited vulnerability (KEV), P0 or P1, a validated exploit, or a crown-jewel or internet-exposed asset. Anyone with approval permission may accept the others alone, with a reason and an end date.'
        ),
      }
    case 'off':
      return {
        label: t('findingApprovals.acceptLevel.off', 'Never'),
        help: t(
          'findingApprovals.acceptLevel.offHelp',
          'Anyone with approval permission may accept the risk of any finding alone, with a reason and an end date.'
        ),
      }
    default:
      return {
        label: t('findingApprovals.acceptLevel.all', 'Always (recommended)'),
        help: t(
          'findingApprovals.acceptLevel.allHelp',
          'Every accepted risk needs a second person to approve it.'
        ),
      }
  }
}

function levelText(t: TFn, kind: ApprovalLevelKind, level: FPApprovalLevel) {
  return kind === 'accept' ? acceptLevelText(t, level) : fpLevelText(t, level)
}

function clampPercent(v: number): number {
  if (!Number.isFinite(v)) return 0
  return Math.min(10, Math.max(0, Math.round(v)))
}

interface LevelSelectorProps {
  kind: ApprovalLevelKind
  value: FPApprovalLevel
  inForce: FPApprovalLevel
  pending?: FPApprovalLevel
  pendingAt?: string
  changed: boolean
  canEdit: boolean
  canceling: boolean
  onChange: (level: FPApprovalLevel) => void
  onCancelPending: () => void
}

/** One level: its choices, the waiting lowering, and the warnings. */
function LevelSelector({
  kind,
  value,
  inForce,
  pending,
  pendingAt,
  changed,
  canEdit,
  canceling,
  onChange,
  onCancelPending,
}: LevelSelectorProps) {
  const { t } = useTranslation()
  const id = useId()
  const title =
    kind === 'accept'
      ? t('findingApprovals.acceptLevel.title', 'Risk acceptance')
      : t('findingApprovals.fpLevel.title', 'False positive')
  const description =
    kind === 'accept'
      ? t(
          'findingApprovals.acceptLevel.description',
          'When accepting the risk of a finding needs a second person. Bulk changes, suppression rules, task exceptions, imports and automation always need one.'
        )
      : t(
          'findingApprovals.fpLevel.description',
          'When marking a finding a false positive needs a second person.'
        )
  const at = pendingAt ? new Date(pendingAt).toLocaleString() : ''
  return (
    <fieldset className="min-w-0 space-y-3" aria-labelledby={`${id}-title`}>
      <div className="space-y-1">
        <h3 id={`${id}-title`} className="text-sm font-semibold">
          {title}
        </h3>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {pending && (
        <Alert>
          <Clock className="h-4 w-4" aria-hidden />
          <AlertTitle>
            {t('findingApprovals.fpLevel.pendingTitle', 'A lower level is waiting')}
          </AlertTitle>
          <AlertDescription>
            {t(
              'findingApprovals.fpLevel.pendingBody',
              '"{level}" takes effect at {at}. Until then "{current}" applies.',
              {
                level: levelText(t, kind, pending).label,
                current: levelText(t, kind, inForce).label,
                at,
              }
            )}
          </AlertDescription>
          {canEdit && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="col-start-2 mt-2 justify-self-start"
              disabled={canceling}
              onClick={onCancelPending}
            >
              {t('findingApprovals.settings.cancelPending', 'Cancel the change')}
            </Button>
          )}
        </Alert>
      )}
      <RadioGroup
        value={value}
        onValueChange={(v) => onChange(v as FPApprovalLevel)}
        disabled={!canEdit}
        aria-label={title}
        className="space-y-3"
      >
        {LEVELS.map((l) => {
          const text = levelText(t, kind, l)
          return (
            <div key={l} className="flex items-start gap-3">
              <RadioGroupItem value={l} id={`${id}-${l}`} className="mt-1" />
              <Label htmlFor={`${id}-${l}`} className="grid gap-1 font-normal">
                <span className="font-medium">{text.label}</span>
                <span className="text-sm text-muted-foreground">{text.help}</span>
              </Label>
            </div>
          )
        })}
      </RadioGroup>
      {value === 'off' && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" aria-hidden />
          <AlertTitle>
            {kind === 'accept'
              ? t('findingApprovals.acceptLevel.offWarningTitle', 'One person can accept any risk')
              : t('findingApprovals.fpLevel.offWarningTitle', 'One person can hide any finding')}
          </AlertTitle>
          <AlertDescription>
            {kind === 'accept'
              ? t(
                  'findingApprovals.acceptLevel.offWarning',
                  'A single stolen session or a single mistake can accept the risk of a critical finding. Decisions stay audited, end on their date, appear in the approvals digest and get a review flag when the finding later changes, but nobody checks them first.'
                )
              : t(
                  'findingApprovals.fpLevel.offWarning',
                  'A single stolen session or a single mistake can mark a critical finding a false positive. Decisions stay audited and get a review flag when the finding later changes, but nobody checks them first.'
                )}
          </AlertDescription>
        </Alert>
      )}
      {changed && LEVELS.indexOf(value) > LEVELS.indexOf(inForce) && (
        <p className="text-sm text-muted-foreground">
          {t(
            'findingApprovals.fpLevel.lowerDelay',
            'A lower level takes effect 24 hours after you save it, and every approver is told. A higher level takes effect at once.'
          )}
        </p>
      )}
    </fieldset>
  )
}

/** The unsaved values of the approval levels section. */
export interface LevelsDraft {
  email: string
  fpLevel: FPApprovalLevel
  acceptLevel: FPApprovalLevel
  percent: number
}

/** The values last chosen: a waiting lower value, else the one in force. */
export function levelsFromSettings(s: FindingApprovalSettings): LevelsDraft {
  return {
    email: s.backup_contact_email ?? '',
    fpLevel: s.pending_fp_approval ?? s.fp_approval ?? 'all',
    acceptLevel: s.pending_accept_approval ?? s.accept_approval ?? 'all',
    percent: s.pending_second_look_percent ?? s.second_look_percent ?? 0,
  }
}

/** What changed against the saved values, field by field. */
export function levelsChanged(draft: LevelsDraft, s: FindingApprovalSettings) {
  const saved = levelsFromSettings(s)
  return {
    email: draft.email.trim() !== saved.email,
    fp: draft.fpLevel !== saved.fpLevel,
    accept: draft.acceptLevel !== saved.acceptLevel,
    percent: draft.percent !== saved.percent,
  }
}

/** The PATCH fields of this section: only the ones that changed. */
export function levelsBody(
  draft: LevelsDraft,
  s: FindingApprovalSettings
): FindingApprovalSettingsUpdate {
  const c = levelsChanged(draft, s)
  return {
    ...(c.email ? { backup_contact_email: draft.email.trim() } : {}),
    ...(c.fp ? { fp_approval: draft.fpLevel } : {}),
    ...(c.accept ? { accept_approval: draft.acceptLevel } : {}),
    ...(c.percent ? { second_look_percent: draft.percent } : {}),
  }
}

/** The names of the changed settings, for the save bar. */
export function levelsChangeNames(t: TFn, draft: LevelsDraft, s: FindingApprovalSettings) {
  const c = levelsChanged(draft, s)
  return [
    c.fp && t('findingApprovals.fpLevel.title', 'False positive'),
    c.accept && t('findingApprovals.acceptLevel.title', 'Risk acceptance'),
    c.percent && t('findingApprovals.fpLevel.secondLookName', 'Second look'),
    c.email && t('findingApprovals.settings.backupTitle', 'Backup contact'),
  ].filter((n): n is string => typeof n === 'string')
}

interface ApprovalLevelsSectionProps {
  settings: FindingApprovalSettings
  draft: LevelsDraft
  onChange: (next: LevelsDraft) => void
  canEdit: boolean
  onSaved?: (next: FindingApprovalSettings) => void
}

/** The "Approval policy" section: both levels, the second look, the backup contact. */
export function ApprovalLevelsSection({
  settings,
  draft,
  onChange,
  canEdit,
  onSaved,
}: ApprovalLevelsSectionProps) {
  const { t } = useTranslation()
  const id = useId()
  const fpInForce: FPApprovalLevel = settings.fp_approval ?? 'all'
  const acceptInForce: FPApprovalLevel = settings.accept_approval ?? 'all'
  const percentInForce = settings.second_look_percent ?? 0
  const changed = levelsChanged(draft, settings)
  const [canceling, setCanceling] = useState<'fp' | 'accept' | 'percent' | null>(null)
  const set = <K extends keyof LevelsDraft>(key: K, value: LevelsDraft[K]) =>
    onChange({ ...draft, [key]: value })

  const pendingPercentAt = settings.pending_second_look_at
    ? new Date(settings.pending_second_look_at).toLocaleString()
    : ''

  // Cancel the waiting lowerings: the API drops them all and keeps the values
  // in force (`what` only says which button shows the busy state). It applies
  // at once, apart from the save bar.
  const cancelPending = async (what: 'fp' | 'accept' | 'percent') => {
    setCanceling(what)
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
      setCanceling(null)
    }
  }

  return (
    <SettingsSection
      framed
      id="approval-levels"
      title={t('findingApprovals.approvalPolicy.title', 'Approval policy')}
      description={t(
        'findingApprovals.approvalPolicy.description',
        'Whether a second person must approve before a finding is marked a false positive or its risk is accepted. The two settings are separate. Whoever decides, a reason is required, the decision is audited and an accepted risk ends on its date.'
      )}
    >
      <SettingsBlock>
        <div className="grid min-w-0 gap-6 @[45rem]:grid-cols-2">
          <LevelSelector
            kind="fp"
            value={draft.fpLevel}
            inForce={fpInForce}
            pending={settings.pending_fp_approval}
            pendingAt={settings.pending_fp_approval_at}
            changed={changed.fp}
            canEdit={canEdit}
            canceling={canceling !== null}
            onChange={(v) => set('fpLevel', v)}
            onCancelPending={() => void cancelPending('fp')}
          />
          <LevelSelector
            kind="accept"
            value={draft.acceptLevel}
            inForce={acceptInForce}
            pending={settings.pending_accept_approval}
            pendingAt={settings.pending_accept_approval_at}
            changed={changed.accept}
            canEdit={canEdit}
            canceling={canceling !== null}
            onChange={(v) => set('acceptLevel', v)}
            onCancelPending={() => void cancelPending('accept')}
          />
        </div>
      </SettingsBlock>
      {settings.pending_second_look_percent !== undefined && (
        <SettingsBlock>
          <Alert>
            <Clock className="h-4 w-4" aria-hidden />
            <AlertTitle>
              {t(
                'findingApprovals.fpLevel.pendingPercentTitle',
                'A lower second-look share is waiting'
              )}
            </AlertTitle>
            <AlertDescription>
              {t(
                'findingApprovals.fpLevel.pendingPercentBody',
                '{next} % takes effect at {at}. Until then {current} % of single-person decisions get a second look.',
                {
                  next: String(settings.pending_second_look_percent),
                  current: String(percentInForce),
                  at: pendingPercentAt,
                }
              )}
            </AlertDescription>
            {canEdit && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="col-start-2 mt-2 justify-self-start"
                disabled={canceling !== null}
                onClick={() => void cancelPending('percent')}
              >
                {t('findingApprovals.settings.cancelPending', 'Cancel the change')}
              </Button>
            )}
          </Alert>
        </SettingsBlock>
      )}
      <SettingsRow
        label={
          <label htmlFor={`${id}-second-look`}>
            {t('findingApprovals.fpLevel.secondLook', 'Second look (% of single-person decisions)')}
          </label>
        }
        hintId={`${id}-second-look-hint`}
        hint={
          <>
            {t(
              'findingApprovals.fpLevel.secondLookHelp',
              'A random share of false positives decided by one person is flagged for another person to look at. 0 turns it off; at most 10.'
            )}
            {changed.percent && draft.percent < percentInForce && (
              <>
                {' '}
                {t(
                  'findingApprovals.fpLevel.lowerPercentDelay',
                  'A lower second-look share takes effect 24 hours after you save it. A higher share takes effect at once.'
                )}
              </>
            )}
          </>
        }
      >
        <Input
          id={`${id}-second-look`}
          type="number"
          min={0}
          max={10}
          step={1}
          value={draft.percent}
          disabled={!canEdit}
          aria-describedby={`${id}-second-look-hint`}
          onChange={(e) => set('percent', clampPercent(Number(e.target.value)))}
          className="w-28"
        />
      </SettingsRow>
      <SettingsRow
        wide
        label={
          <label htmlFor={`${id}-email`}>
            {t('findingApprovals.settings.backupTitle', 'Backup contact')}
          </label>
        }
        hintId={`${id}-email-hint`}
        hint={t(
          'findingApprovals.settings.backupDescription',
          'An advisor or auditor outside the organization who is emailed whenever its only member approves their own finding request.'
        )}
      >
        <Input
          id={`${id}-email`}
          type="email"
          maxLength={254}
          autoComplete="email"
          aria-describedby={`${id}-email-hint`}
          placeholder={t('findingApprovals.settings.backupPlaceholder', 'advisor@example.com')}
          value={draft.email}
          disabled={!canEdit}
          onChange={(e) => set('email', e.target.value)}
        />
      </SettingsRow>
    </SettingsSection>
  )
}
