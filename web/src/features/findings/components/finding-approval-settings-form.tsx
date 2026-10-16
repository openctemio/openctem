'use client'

/**
 * Settings > Finding approvals: how the organization governs false-positive
 * and accepted-risk decisions (api/docs/architecture/finding-status-lifecycle.md).
 * Saving needs settings:write and a recent sign-in (the API client asks for
 * re-authentication); every change is audited and the approvers are told. A
 * lower false-positive level takes effect 24 hours later; a higher one at once.
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

const LEVELS: FPApprovalLevel[] = ['all', 'high_and_above', 'off']

/** The level's label and explanation. */
export function fpLevelText(
  t: ReturnType<typeof useTranslation>['t'],
  level: FPApprovalLevel
): { label: string; help: string } {
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

function clampPercent(v: number): number {
  if (!Number.isFinite(v)) return 0
  return Math.min(10, Math.max(0, Math.round(v)))
}

export function FindingApprovalSettingsForm({
  settings,
  canEdit,
  onSaved,
}: FindingApprovalSettingsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const inForce: FPApprovalLevel = settings.fp_approval ?? 'all'
  // The level last chosen: a waiting lower level, else the one in force.
  const chosen: FPApprovalLevel = settings.pending_fp_approval ?? inForce
  const [email, setEmail] = useState(settings.backup_contact_email ?? '')
  const [level, setLevel] = useState<FPApprovalLevel>(chosen)
  const percentInForce = settings.second_look_percent ?? 0
  // The share last chosen: a waiting lower share, else the one in force.
  const chosenPercent = settings.pending_second_look_percent ?? percentInForce
  const [percent, setPercent] = useState(chosenPercent)
  const [saving, setSaving] = useState(false)
  const [canceling, setCanceling] = useState<'level' | 'percent' | null>(null)

  useEffect(() => {
    setEmail(settings.backup_contact_email ?? '')
    setLevel(settings.pending_fp_approval ?? settings.fp_approval ?? 'all')
    setPercent(settings.pending_second_look_percent ?? settings.second_look_percent ?? 0)
  }, [
    settings.backup_contact_email,
    settings.fp_approval,
    settings.pending_fp_approval,
    settings.second_look_percent,
    settings.pending_second_look_percent,
  ])

  const emailChanged = email.trim() !== (settings.backup_contact_email ?? '')
  const levelChanged = level !== chosen
  const percentChanged = percent !== chosenPercent
  const dirty = emailChanged || levelChanged || percentChanged

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const next = await updateFindingApprovalSettings({
        ...(emailChanged ? { backup_contact_email: email.trim() } : {}),
        ...(levelChanged ? { fp_approval: level } : {}),
        ...(percentChanged ? { second_look_percent: percent } : {}),
      })
      toast.success(
        (next?.pending_fp_approval && levelChanged) ||
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

  const pendingAt = settings.pending_fp_approval_at
    ? new Date(settings.pending_fp_approval_at).toLocaleString()
    : ''
  const pendingPercentAt = settings.pending_second_look_at
    ? new Date(settings.pending_second_look_at).toLocaleString()
    : ''

  // Cancel a waiting lowering: choosing the value in force again applies at
  // once and clears the pending change (the API treats it as a raise).
  const cancelPending = async (what: 'level' | 'percent') => {
    setCanceling(what)
    try {
      const next = await updateFindingApprovalSettings(
        what === 'level' ? { fp_approval: inForce } : { second_look_percent: percentInForce }
      )
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
            {t('findingApprovals.fpLevel.title', 'False-positive approval')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.fpLevel.description',
              'When marking a finding a false positive needs a second person. An accepted risk always needs a second person, whatever you choose here.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {settings.pending_fp_approval && (
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
                    level: fpLevelText(t, settings.pending_fp_approval).label,
                    current: fpLevelText(t, inForce).label,
                    at: pendingAt,
                  }
                )}
              </AlertDescription>
              {canEdit && (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="mt-2"
                  disabled={canceling !== null}
                  onClick={() => void cancelPending('level')}
                >
                  {t('findingApprovals.settings.cancelPending', 'Cancel the change')}
                </Button>
              )}
            </Alert>
          )}
          <RadioGroup
            value={level}
            onValueChange={(v) => setLevel(v as FPApprovalLevel)}
            disabled={!canEdit}
            aria-label={t('findingApprovals.fpLevel.title', 'False-positive approval')}
            className="space-y-3"
          >
            {LEVELS.map((l) => {
              const text = fpLevelText(t, l)
              return (
                <div key={l} className="flex items-start gap-3">
                  <RadioGroupItem value={l} id={`${id}-level-${l}`} className="mt-1" />
                  <Label htmlFor={`${id}-level-${l}`} className="grid gap-1 font-normal">
                    <span className="font-medium">{text.label}</span>
                    <span className="text-sm text-muted-foreground">{text.help}</span>
                  </Label>
                </div>
              )
            })}
          </RadioGroup>
          {level === 'off' && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" aria-hidden />
              <AlertTitle>
                {t('findingApprovals.fpLevel.offWarningTitle', 'One person can hide any finding')}
              </AlertTitle>
              <AlertDescription>
                {t(
                  'findingApprovals.fpLevel.offWarning',
                  'A single stolen session or a single mistake can mark a critical finding a false positive. Decisions stay audited and get a review flag when the finding later changes, but nobody checks them first.'
                )}
              </AlertDescription>
            </Alert>
          )}
          {levelChanged && LEVELS.indexOf(level) > LEVELS.indexOf(inForce) && (
            <p className="text-sm text-muted-foreground">
              {t(
                'findingApprovals.fpLevel.lowerDelay',
                'A lower level takes effect 24 hours after you save it, and every approver is told. A higher level takes effect at once.'
              )}
            </p>
          )}
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
                  className="mt-2"
                  disabled={canceling !== null}
                  onClick={() => void cancelPending('percent')}
                >
                  {t('findingApprovals.settings.cancelPending', 'Cancel the change')}
                </Button>
              )}
            </Alert>
          )}
          <div className="space-y-2">
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
