'use client'

/**
 * Settings > Approvals, the approval levels: the organization's levels for
 * false positives and accepted risks, the second-look share and the backup
 * contact (server/docs/architecture/finding-status-lifecycle.md, "Approval
 * levels"). Their draft helpers and the level selector the editors draw
 * (`approval-editors.tsx`); `FindingApprovalsForm` saves them.
 * Saving needs settings:write and a recent sign-in (the API client asks for
 * re-authentication); every change is audited and the approvers are told. A
 * lower level takes effect 24 hours later; a higher one at once.
 */

import { useId } from 'react'
import { AlertTriangle, Clock } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import {
  type FindingApprovalSettings,
  type FindingApprovalSettingsUpdate,
  type FPApprovalLevel,
} from '../api/use-findings-api'
import { formatDateTime } from '@/lib/app-locale'

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

export function clampPercent(v: number): number {
  if (!Number.isFinite(v)) return 0
  return Math.min(10, Math.max(0, Math.round(v)))
}

export interface LevelSelectorProps {
  kind: ApprovalLevelKind
  value: FPApprovalLevel
  inForce: FPApprovalLevel
  pending?: FPApprovalLevel
  pendingAt?: string
  changed: boolean
  canEdit: boolean
  onChange: (level: FPApprovalLevel) => void
}

/** What a level decides, in one sentence (the editor's description). */
export function levelDescription(t: TFn, kind: ApprovalLevelKind): string {
  return kind === 'accept'
    ? t(
        'findingApprovals.acceptLevel.description',
        'When accepting the risk of a finding needs a second person. Bulk changes, suppression rules, task exceptions, imports and automation always need one.'
      )
    : t(
        'findingApprovals.fpLevel.description',
        'When marking a finding a false positive needs a second person.'
      )
}

/** One level: its choices, the waiting lowering, and the warnings. */
export function LevelSelector({
  kind,
  value,
  inForce,
  pending,
  pendingAt,
  changed,
  canEdit,
  onChange,
}: LevelSelectorProps) {
  const { t } = useTranslation()
  const id = useId()
  const title =
    kind === 'accept'
      ? t('findingApprovals.acceptLevel.title', 'Risk acceptance')
      : t('findingApprovals.fpLevel.title', 'False positive')
  const at = pendingAt ? formatDateTime(new Date(pendingAt)) : ''
  return (
    <fieldset className="min-w-0 space-y-3" aria-labelledby={`${id}-title`}>
      {/* The editor's title says what the choice is about: named for readers only. */}
      <h3 id={`${id}-title`} className="sr-only">
        {title}
      </h3>
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
