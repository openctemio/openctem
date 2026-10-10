'use client'

/**
 * The platform policy for scope-widening approvals (RFC-054 §12.6), used by
 * System > Scope approvals (the platform default) and an organization's
 * Scope tab (its override). Relaxing approvals never turns scope off:
 * step-up, the dry run, ownership proof, the platform deny list, audit and
 * the notification of every tenant administrator stay. A change needs a
 * reason and a fresh authenticator code; it is recorded in the admin audit
 * log, the other administrators are emailed and, for an organization, its
 * administrators are told.
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
import { AdminApiError } from '../api/admin-client'
import type { ScopeApprovalMode } from '../api/use-scope-policy'

export const SCOPE_POLICY_TEXT: Record<ScopeApprovalMode, { label: string; hint: string }> = {
  required: {
    label: 'Approvals required',
    hint: 'Widening scope waits for another approver: the organization sets 0, 1 or 2, at least 1 with two or more administrators and always 1 for intrusive (T2) entries.',
  },
  tenant_controlled: {
    label: 'The organization decides',
    hint: "The organization's owner sets 0, 1 or 2 approvals for every tier, intrusive (T2) included.",
  },
  disabled: {
    label: 'No approvals',
    hint: 'Widening takes effect without a second person, for every tier. A member’s request still needs an approver.',
  },
}

const INHERIT = 'inherit'

export interface ScopePolicyFormProps {
  title: string
  description: string
  /** The stored mode; null follows the platform default (organizations only). */
  value: ScopeApprovalMode | null
  /** Organizations: the platform default, offered as "Follow the platform default". */
  platformDefault?: ScopeApprovalMode
  canEdit: boolean
  onSave: (mode: ScopeApprovalMode | null, reason: string, code: string) => Promise<void>
}

export function ScopePolicyForm({
  title,
  description,
  value,
  platformDefault,
  canEdit,
  onSave,
}: ScopePolicyFormProps) {
  const id = useId()
  const inherits = platformDefault !== undefined
  const initial = value ?? (inherits ? INHERIT : 'required')
  const [choice, setChoice] = useState<string>(initial)
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => setChoice(value ?? (inherits ? INHERIT : 'required')), [value, inherits])

  const next = choice === INHERIT ? null : (choice as ScopeApprovalMode)
  const dirty = choice !== initial

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await onSave(next, reason.trim(), code.trim())
      setOpen(false)
      setReason('')
      toast.success('Scope approval policy saved')
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setOpen(false)
      toast.error(e instanceof Error ? e.message : 'Could not save the policy')
    } finally {
      setBusy(false)
    }
  }

  const modes = Object.keys(SCOPE_POLICY_TEXT) as ScopeApprovalMode[]

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
            aria-label="Scope approval policy"
          >
            {inherits && (
              <div className="flex items-start gap-3">
                <RadioGroupItem value={INHERIT} id={`${id}-inherit`} className="mt-1" />
                <Label htmlFor={`${id}-inherit`} className="grid gap-1 font-normal">
                  <span className="font-medium">Follow the platform default</span>
                  <span className="text-sm text-muted-foreground">
                    Now: {SCOPE_POLICY_TEXT[platformDefault ?? 'required'].label}.
                  </span>
                </Label>
              </div>
            )}
            {modes.map((m) => (
              <div key={m} className="flex items-start gap-3">
                <RadioGroupItem value={m} id={`${id}-${m}`} className="mt-1" />
                <Label htmlFor={`${id}-${m}`} className="grid gap-1 font-normal">
                  <span className="font-medium">{SCOPE_POLICY_TEXT[m].label}</span>
                  <span className="text-sm text-muted-foreground">{SCOPE_POLICY_TEXT[m].hint}</span>
                </Label>
              </div>
            ))}
          </RadioGroup>
          <p className="text-sm text-muted-foreground">
            In every mode, widening still needs re-authentication, ownership proof for intrusive
            probes and platform sensors, and passes the platform deny list; every administrator of
            the organization is told and the change is audited. Scope itself is never turned off.
          </p>
          {canEdit ? (
            <div className="flex justify-end">
              <Button onClick={() => setOpen(true)} disabled={!dirty || busy}>
                Save
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Only a super admin can change it.</p>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          if (!busy) setOpen(o)
        }}
        title="Change the scope approval policy?"
        desc={
          <p>
            New policy:{' '}
            <strong>{next ? SCOPE_POLICY_TEXT[next].label : 'Follow the platform default'}</strong>.
            The change is recorded in the admin audit log; the other administrators are emailed.
          </p>
        }
        disabled={code.trim().length < 6 || !reason.trim()}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              Saving
            </>
          ) : (
            'Confirm'
          )
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={`${id}-reason`}>Reason</Label>
            <Textarea
              id={`${id}-reason`}
              rows={2}
              maxLength={1000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-code`}>Code from your authenticator</Label>
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
