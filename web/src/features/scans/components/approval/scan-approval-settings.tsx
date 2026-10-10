'use client'

/**
 * Settings > Scan approval (RFC-073): the organization's mode (Off, On,
 * Strict; owner only) and its approval rules (owner or administrator):
 * apply a preset, turn a rule off, put it in monitor mode, or remove it.
 * Every change asks for a reason; the API asks for re-authentication. The
 * full rule builder and the rule tester come later.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  saveScanGovernanceMode,
  saveScanGovernanceRules,
  useScanGovernance,
  type ScanApprovalMode,
  type ScanApprovalRule,
} from '@/lib/api/scan-approval-hooks'
import { usePermissions } from '@/lib/permissions'
import { approversText } from './approval-requirement'

type Pending =
  | { kind: 'mode'; mode: ScanApprovalMode }
  | { kind: 'rules'; rules: ScanApprovalRule[]; label: string }

const MODES: ScanApprovalMode[] = ['off', 'on', 'strict']
const PRESETS = ['light', 'standard', 'strict'] as const

export function ScanApprovalSettings() {
  const { t } = useTranslation()
  const id = useId()
  const { isOwner, isAdmin } = usePermissions()
  const { data, error, isLoading, mutate } = useScanGovernance()
  const [choice, setChoice] = useState<ScanApprovalMode>('off')
  const [pending, setPending] = useState<Pending | null>(null)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (data) setChoice(data.organization_mode)
  }, [data])

  if (error) {
    return (
      <ErrorState
        title={t('scans.approvalSettings.errorTitle', 'the scan approval settings')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-96 w-full" />

  const canMode = isOwner()
  const canRules = isOwner() || isAdmin()
  const modeText: Record<ScanApprovalMode, { label: string; hint: string }> = {
    off: {
      label: t('scans.approvalSettings.off', 'Off'),
      hint: t(
        'scans.approvalSettings.offHint',
        'No scan needs approval. Members with scan permission create and run scans directly; scope entries take effect at once.'
      ),
    },
    on: {
      label: t('scans.approvalSettings.on', 'On'),
      hint: t(
        'scans.approvalSettings.onHint',
        'The rules below decide which scans need approval. Runs of an approved scan need nothing more; a change needs a new approval.'
      ),
    },
    strict: {
      label: t('scans.approvalSettings.strict', 'Strict'),
      hint: t(
        'scans.approvalSettings.strictHint',
        'As On, with two distinct approvers and a justification for every caught scan; scope entries need approval too.'
      ),
    },
  }

  const save = async () => {
    if (!pending) return
    setBusy(true)
    try {
      if (pending.kind === 'mode') {
        await saveScanGovernanceMode(pending.mode, reason.trim())
      } else {
        await saveScanGovernanceRules(pending.rules, data.pending_expiry_days, reason.trim())
      }
      toast.success(t('scans.approvalSettings.saved', 'Scan approval saved'))
      setPending(null)
      setReason('')
      await mutate()
    } catch (e) {
      toast.error(getErrorMessage(e, t('scans.approvalSettings.saveFailed', 'Could not save')))
    } finally {
      setBusy(false)
    }
  }

  const changeRule = (i: number, patch: Partial<ScanApprovalRule>, label: string) => {
    const rules = data.rules.map((r, j) => (j === i ? { ...r, ...patch } : r))
    setPending({ kind: 'rules', rules, label })
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{t('scans.approvalSettings.title', 'Scan approval')}</CardTitle>
          <CardDescription>
            {data.source === 'platform'
              ? t(
                  'scans.approvalSettings.forced',
                  'In force: {mode}, set by your platform administrator.',
                  {
                    mode: modeText[data.mode].label,
                  }
                )
              : t('scans.approvalSettings.inForce', 'In force: {mode}.', {
                  mode: modeText[data.mode].label,
                })}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <RadioGroup
            value={choice}
            onValueChange={(v) => setChoice(v as ScanApprovalMode)}
            disabled={!canMode}
            aria-label={t('scans.approvalSettings.title', 'Scan approval')}
          >
            {MODES.map((m) => (
              <div key={m} className="flex items-start gap-3">
                <RadioGroupItem
                  value={m}
                  id={`${id}-${m}`}
                  className="mt-1"
                  disabled={!data.selectable_modes.includes(m)}
                />
                <Label htmlFor={`${id}-${m}`} className="grid gap-1 font-normal">
                  <span className="font-medium">{modeText[m].label}</span>
                  <span className="text-sm text-muted-foreground">{modeText[m].hint}</span>
                </Label>
              </div>
            ))}
          </RadioGroup>
          {canMode ? (
            <div className="flex justify-end">
              <Button
                disabled={choice === data.organization_mode || busy}
                onClick={() => setPending({ kind: 'mode', mode: choice })}
              >
                {t('scans.approvalSettings.save', 'Save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('scans.approvalSettings.ownerOnly', 'Only an owner changes the mode.')}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('scans.approvalSettings.rulesTitle', 'Approval rules')}</CardTitle>
          <CardDescription>
            {t(
              'scans.approvalSettings.rulesDesc',
              'Conditions inside a rule must all hold; any matching rule holds the scan. The matching rule with the most approvers decides who approves. Monitor mode records what a rule would hold without holding it.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {canRules && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm text-muted-foreground">
                {t('scans.approvalSettings.presets', 'Start from a preset:')}
              </span>
              {PRESETS.map((p) => (
                <Button
                  key={p}
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    setPending({
                      kind: 'rules',
                      rules: data.presets[p] ?? [],
                      label: t(
                        'scans.approvalSettings.applyPreset',
                        'Replace the rules with the {preset} preset',
                        {
                          preset: t(`scans.approvalSettings.preset.${p}`, p),
                        }
                      ),
                    })
                  }
                >
                  {t(`scans.approvalSettings.preset.${p}`, p)}
                </Button>
              ))}
            </div>
          )}
          {data.rules.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t(
                'scans.approvalSettings.noRules',
                'No rules: no scan needs approval even when the mode is On.'
              )}
            </p>
          ) : (
            <ul className="divide-y rounded-md border">
              {data.rules.map((r, i) => (
                <li key={r.id} className="flex flex-wrap items-center gap-3 p-3">
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{r.name}</span>
                      {r.monitor && (
                        <Badge variant="outline">
                          {t('scans.approvalSettings.monitor', 'Monitor')}
                        </Badge>
                      )}
                      {!r.enabled && (
                        <Badge variant="secondary">
                          {t('scans.approvalSettings.disabled', 'Off')}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {approversText(t, {
                        mode: data.mode,
                        required: true,
                        approvals: r.requirement.approvals,
                        approver_roles: r.requirement.approver_roles,
                        approver_user_ids: r.requirement.approver_user_ids,
                      })}
                    </p>
                  </div>
                  {canRules && (
                    <div className="flex items-center gap-3">
                      <label className="flex items-center gap-2 text-sm">
                        <Switch
                          checked={r.enabled}
                          onCheckedChange={(v) =>
                            changeRule(
                              i,
                              { enabled: v },
                              t('scans.approvalSettings.toggleRule', 'Change rule "{name}"', {
                                name: r.name,
                              })
                            )
                          }
                          aria-label={t('scans.approvalSettings.enabled', 'Enabled')}
                        />
                        {t('scans.approvalSettings.enabled', 'Enabled')}
                      </label>
                      <label className="flex items-center gap-2 text-sm">
                        <Switch
                          checked={!!r.monitor}
                          onCheckedChange={(v) =>
                            changeRule(
                              i,
                              { monitor: v },
                              t('scans.approvalSettings.toggleRule', 'Change rule "{name}"', {
                                name: r.name,
                              })
                            )
                          }
                          aria-label={t('scans.approvalSettings.monitor', 'Monitor')}
                        />
                        {t('scans.approvalSettings.monitor', 'Monitor')}
                      </label>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          setPending({
                            kind: 'rules',
                            rules: data.rules.filter((_, j) => j !== i),
                            label: t('scans.approvalSettings.removeRule', 'Remove rule "{name}"', {
                              name: r.name,
                            }),
                          })
                        }
                      >
                        {t('scans.approvalSettings.remove', 'Remove')}
                      </Button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!pending} onOpenChange={(o) => !busy && !o && setPending(null)}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>
              {t('scans.approvalSettings.confirmTitle', 'Change scan approval?')}
            </DialogTitle>
            <DialogDescription>
              {pending?.kind === 'mode'
                ? t('scans.approvalSettings.confirmMode', 'New mode: {mode}.', {
                    mode: modeText[pending.mode].label,
                  })
                : pending?.label}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-1">
            <Label htmlFor={`${id}-reason`}>{t('scans.approvalSettings.reason', 'Reason')}</Label>
            <Textarea
              id={`${id}-reason`}
              rows={2}
              maxLength={1000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button onClick={() => void save()} disabled={busy || !reason.trim()}>
              {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
              {t('scans.approvalSettings.confirm', 'Confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
