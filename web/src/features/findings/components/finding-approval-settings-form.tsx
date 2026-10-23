'use client'

/**
 * Settings > Finding approvals: the organization's approval policy for
 * false positives and accepted risks, the second-look share and the backup
 * contact (api/docs/architecture/finding-status-lifecycle.md, "Approval
 * levels"). Saving needs settings:write and a recent sign-in (the API client
 * asks for re-authentication); every change is audited and the approvers are
 * told. A lower level takes effect 24 hours later; a higher one at once.
 */

import { useEffect, useId, useState } from 'react'
import { AlertTriangle, Clock, Loader2, Save } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  updateFindingApprovalSettings,
  type FindingApprovalSettings,
  type FPApprovalLevel,
} from '../api/use-findings-api'

interface FindingApprovalSettingsFormProps {
  settings: FindingApprovalSettings
  canEdit: boolean
  onSaved?: (next: FindingApprovalSettings) => void
}

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

export function FindingApprovalSettingsForm({
  settings,
  canEdit,
  onSaved,
}: FindingApprovalSettingsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const fpInForce: FPApprovalLevel = settings.fp_approval ?? 'all'
  const acceptInForce: FPApprovalLevel = settings.accept_approval ?? 'all'
  // The level last chosen: a waiting lower level, else the one in force.
  const fpChosen: FPApprovalLevel = settings.pending_fp_approval ?? fpInForce
  const acceptChosen: FPApprovalLevel = settings.pending_accept_approval ?? acceptInForce
  const [email, setEmail] = useState(settings.backup_contact_email ?? '')
  const [fpLevel, setFPLevel] = useState<FPApprovalLevel>(fpChosen)
  const [acceptLevel, setAcceptLevel] = useState<FPApprovalLevel>(acceptChosen)
  const percentInForce = settings.second_look_percent ?? 0
  // The share last chosen: a waiting lower share, else the one in force.
  const chosenPercent = settings.pending_second_look_percent ?? percentInForce
  const [percent, setPercent] = useState(chosenPercent)
  const [saving, setSaving] = useState(false)
  const [canceling, setCanceling] = useState<'fp' | 'accept' | 'percent' | null>(null)

  useEffect(() => {
    setEmail(settings.backup_contact_email ?? '')
    setFPLevel(settings.pending_fp_approval ?? settings.fp_approval ?? 'all')
    setAcceptLevel(settings.pending_accept_approval ?? settings.accept_approval ?? 'all')
    setPercent(settings.pending_second_look_percent ?? settings.second_look_percent ?? 0)
  }, [
    settings.backup_contact_email,
    settings.fp_approval,
    settings.pending_fp_approval,
    settings.accept_approval,
    settings.pending_accept_approval,
    settings.second_look_percent,
    settings.pending_second_look_percent,
  ])

  const emailChanged = email.trim() !== (settings.backup_contact_email ?? '')
  const fpChanged = fpLevel !== fpChosen
  const acceptChanged = acceptLevel !== acceptChosen
  const percentChanged = percent !== chosenPercent
  const dirty = emailChanged || fpChanged || acceptChanged || percentChanged

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const next = await updateFindingApprovalSettings({
        ...(emailChanged ? { backup_contact_email: email.trim() } : {}),
        ...(fpChanged ? { fp_approval: fpLevel } : {}),
        ...(acceptChanged ? { accept_approval: acceptLevel } : {}),
        ...(percentChanged ? { second_look_percent: percent } : {}),
      })
      toast.success(
        (next?.pending_fp_approval && fpChanged) ||
          (next?.pending_accept_approval && acceptChanged) ||
          (next?.pending_second_look_percent !== undefined && percentChanged)
          ? t(
              'findingApprovals.settings.savedPending',
              'Saved. The lower level takes effect in 24 hours; the approvers were told.'
            )
          : t('findingApprovals.settings.saved', 'Finding approval settings saved')
      )
      onSaved?.(next)
    } catch (err) {
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

  const pendingPercentAt = settings.pending_second_look_at
    ? new Date(settings.pending_second_look_at).toLocaleString()
    : ''

  // Cancel the waiting lowerings: the API drops them all and keeps the values
  // in force (`what` only says which button shows the busy state).
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
    <form onSubmit={save} className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('findingApprovals.approvalPolicy.title', 'Approval policy')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.approvalPolicy.description',
              'Whether a second person must approve before a finding is marked a false positive or its risk is accepted. The two settings are separate. Whoever decides, a reason is required, the decision is audited and an accepted risk ends on its date.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            <LevelSelector
              kind="fp"
              value={fpLevel}
              inForce={fpInForce}
              pending={settings.pending_fp_approval}
              pendingAt={settings.pending_fp_approval_at}
              changed={fpChanged}
              canEdit={canEdit}
              canceling={canceling !== null}
              onChange={setFPLevel}
              onCancelPending={() => void cancelPending('fp')}
            />
            <LevelSelector
              kind="accept"
              value={acceptLevel}
              inForce={acceptInForce}
              pending={settings.pending_accept_approval}
              pendingAt={settings.pending_accept_approval_at}
              changed={acceptChanged}
              canEdit={canEdit}
              canceling={canceling !== null}
              onChange={setAcceptLevel}
              onCancelPending={() => void cancelPending('accept')}
            />
          </div>
          {settings.pending_second_look_percent !== undefined && (
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
          )}
          <div className="space-y-2 border-t pt-4">
            <Label htmlFor={`${id}-second-look`}>
              {t(
                'findingApprovals.fpLevel.secondLook',
                'Second look (% of single-person decisions)'
              )}
            </Label>
            <Input
              id={`${id}-second-look`}
              type="number"
              min={0}
              max={10}
              step={1}
              value={percent}
              disabled={!canEdit}
              onChange={(e) => setPercent(clampPercent(Number(e.target.value)))}
              className="w-28"
            />
            {percentChanged && percent < percentInForce && (
              <p className="text-sm text-muted-foreground">
                {t(
                  'findingApprovals.fpLevel.lowerPercentDelay',
                  'A lower second-look share takes effect 24 hours after you save it. A higher share takes effect at once.'
                )}
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              {t(
                'findingApprovals.fpLevel.secondLookHelp',
                'A random share of false positives decided by one person is flagged for another person to look at. 0 turns it off; at most 10.'
              )}
            </p>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('findingApprovals.settings.backupTitle', 'Backup contact')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.settings.backupDescription',
              'An advisor or auditor outside the organization who is emailed whenever its only member approves their own finding request.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <Label htmlFor={`${id}-email`}>
            {t('findingApprovals.settings.backupLabel', 'Email address')}
          </Label>
          <Input
            id={`${id}-email`}
            type="email"
            maxLength={254}
            autoComplete="email"
            placeholder={t('findingApprovals.settings.backupPlaceholder', 'advisor@example.com')}
            value={email}
            disabled={!canEdit}
            onChange={(e) => setEmail(e.target.value)}
            className="max-w-sm"
          />
        </CardContent>
      </Card>
      {canEdit && (
        <div className="flex justify-end">
          <Button type="submit" size="sm" disabled={!dirty || saving}>
            {saving ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Save className="h-4 w-4" aria-hidden />
            )}
            {t('findingApprovals.settings.save', 'Save changes')}
          </Button>
        </div>
      )}
    </form>
  )
}
