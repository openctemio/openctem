'use client'

/**
 * The platform policy for scan approval (RFC-072 §5), used by System > Scan
 * approval (the platform default) and an organization's Scope tab (its
 * override). It lets the organization's owner choose Off, On or Strict, or
 * forces one. Forcing Off never turns scope off: step-up, exclusions,
 * ownership proof, the platform deny list, audit and the notification of
 * every tenant administrator stay. A change needs a reason and a fresh
 * authenticator code; it is recorded in the admin audit log, the other
 * administrators are emailed and, for an organization, its administrators
 * are told.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '../api/admin-client'
import type { ScanApprovalMode, ScanApprovalPolicy } from '../api/use-scan-policy'

const POLICIES: ScanApprovalPolicy[] = ['tenant_controlled', 'off', 'on', 'strict']

/** Label and hint of a policy, translated. */
export function useScanPolicyText() {
  const { t } = useTranslation()
  const policy = (p: ScanApprovalPolicy) =>
    ({
      tenant_controlled: {
        label: t('admin.scanPolicy.tenantControlled', 'The organization decides'),
        hint: t(
          'admin.scanPolicy.tenantControlledHint',
          "The organization's owner turns scan approval off, on or strict. Off by default."
        ),
      },
      off: {
        label: t('admin.scanPolicy.off', 'Off'),
        hint: t(
          'admin.scanPolicy.offHint',
          'No scan needs approval and scope entries take effect without a second person.'
        ),
      },
      on: {
        label: t('admin.scanPolicy.on', 'At least on'),
        hint: t(
          'admin.scanPolicy.onHint',
          "The organization's approval rules apply; its owner may still choose Strict."
        ),
      },
      strict: {
        label: t('admin.scanPolicy.strict', 'Strict'),
        hint: t(
          'admin.scanPolicy.strictHint',
          'Matched scans need two approvers and a justification, and scope entries need approval.'
        ),
      },
    })[p]
  const mode = (m: ScanApprovalMode) =>
    ({
      off: t('admin.scanPolicy.modeOff', 'Off'),
      on: t('admin.scanPolicy.modeOn', 'On'),
      strict: t('admin.scanPolicy.modeStrict', 'Strict'),
    })[m]
  return { policy, mode }
}

const INHERIT = 'inherit'

export interface ScanPolicyFormProps {
  title: string
  description: string
  /** The stored policy; null follows the platform default (organizations only). */
  value: ScanApprovalPolicy | null
  /** Organizations: the platform default, offered as "Follow the platform default". */
  platformDefault?: ScanApprovalPolicy
  canEdit: boolean
  onSave: (policy: ScanApprovalPolicy | null, reason: string, code: string) => Promise<void>
}

export function ScanPolicyForm({
  title,
  description,
  value,
  platformDefault,
  canEdit,
  onSave,
}: ScanPolicyFormProps) {
  const { t } = useTranslation()
  const text = useScanPolicyText()
  const id = useId()
  const inherits = platformDefault !== undefined
  const initial = value ?? (inherits ? INHERIT : 'tenant_controlled')
  const [choice, setChoice] = useState<string>(initial)
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => setChoice(value ?? (inherits ? INHERIT : 'tenant_controlled')), [value, inherits])

  const next = choice === INHERIT ? null : (choice as ScanApprovalPolicy)
  const dirty = choice !== initial

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await onSave(next, reason.trim(), code.trim())
      setOpen(false)
      setReason('')
      toast.success(t('admin.scanPolicy.saved', 'Scan approval policy saved'))
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setOpen(false)
      toast.error(
        e instanceof Error
          ? e.message
          : t('admin.scanPolicy.saveFailed', 'Could not save the policy')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <RadioGroup
            value={choice}
            onValueChange={setChoice}
            disabled={!canEdit}
            aria-label={t('admin.scanPolicy.aria', 'Scan approval policy')}
          >
            {inherits && (
              <div className="flex items-start gap-3">
                <RadioGroupItem value={INHERIT} id={`${id}-inherit`} className="mt-1" />
                <Label htmlFor={`${id}-inherit`} className="grid gap-1 font-normal">
                  <span className="font-medium">
                    {t('admin.scanPolicy.inherit', 'Follow the platform default')}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {t('admin.scanPolicy.inheritNow', 'Now: {policy}.', {
                      policy: text.policy(platformDefault ?? 'tenant_controlled').label,
                    })}
                  </span>
                </Label>
              </div>
            )}
            {POLICIES.map((p) => (
              <div key={p} className="flex items-start gap-3">
                <RadioGroupItem value={p} id={`${id}-${p}`} className="mt-1" />
                <Label htmlFor={`${id}-${p}`} className="grid gap-1 font-normal">
                  <span className="font-medium">{text.policy(p).label}</span>
                  <span className="text-sm text-muted-foreground">{text.policy(p).hint}</span>
                </Label>
              </div>
            ))}
          </RadioGroup>
          <p className="text-sm text-muted-foreground">
            {t(
              'admin.scanPolicy.alwaysOn',
              'In every mode, widening scope still needs re-authentication, ownership proof for platform sensors, and passes the platform deny list; every administrator of the organization is told and the change is audited.'
            )}
          </p>
          {canEdit ? (
            <div className="flex justify-end">
              <Button onClick={() => setOpen(true)} disabled={!dirty || busy}>
                {t('admin.scanPolicy.save', 'Save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('admin.scanPolicy.superOnly', 'Only a super admin can change it.')}
            </p>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          if (!busy) setOpen(o)
        }}
        title={t('admin.scanPolicy.confirmTitle', 'Change the scan approval policy?')}
        desc={
          <p>
            {t(
              'admin.scanPolicy.confirmDesc',
              'New policy: {policy}. The change is recorded in the admin audit log; the other administrators are emailed.',
              {
                policy: next
                  ? text.policy(next).label
                  : t('admin.scanPolicy.inherit', 'Follow the platform default'),
              }
            )}
          </p>
        }
        disabled={code.trim().length < 6 || !reason.trim()}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.scanPolicy.saving', 'Saving')}
            </>
          ) : (
            t('admin.scanPolicy.confirm', 'Confirm')
          )
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={`${id}-reason`}>{t('admin.scanPolicy.reason', 'Reason')}</Label>
            <Textarea
              id={`${id}-reason`}
              rows={2}
              maxLength={1000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-code`}>
              {t('admin.scanPolicy.code', 'Code from your authenticator')}
            </Label>
            <Input
              id={`${id}-code`}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              aria-invalid={!!codeError}
            />
            {codeError && <p className="text-sm text-destructive">{codeError}</p>}
          </div>
        </div>
      </ConfirmDialog>
    </>
  )
}
