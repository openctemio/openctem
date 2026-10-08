'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Switch } from '@/components/ui/switch'
import { RelativeTime } from '@/features/shared'
import type { SignupPolicyResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import { saveSignupPolicy } from '../api/use-signup-policy'

type Mode = 'admin_only' | 'self_service'

const MODE_LABEL: Record<Mode, string> = {
  admin_only: 'Only platform administrators',
  self_service: 'Anyone who signs up',
}

const SOURCE_LABEL: Record<string, string> = {
  environment: 'set from the environment at install',
  console: 'set in this console',
  default: 'not stored yet: the safe default applies',
}

export interface SignupPolicyFormProps {
  policy: SignupPolicyResponse
  /** False for an administrator who may read but not change the policy. */
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Sign-up: who may create an organization on this deployment. A
 * change needs a fresh authenticator code, never touches existing
 * organizations, users or sessions, and is reported to the other
 * administrators.
 */
export function SignupPolicyForm({ policy, canEdit, onSaved }: SignupPolicyFormProps) {
  const [mode, setMode] = useState<Mode>((policy.mode as Mode) ?? 'admin_only')
  const [requestAccess, setRequestAccess] = useState(!!policy.request_access)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const codeId = useId()

  useEffect(() => {
    setMode((policy.mode as Mode) ?? 'admin_only')
    setRequestAccess(!!policy.request_access)
  }, [policy.mode, policy.request_access, policy.version])

  const dirty = mode !== policy.mode || requestAccess !== !!policy.request_access

  const openConfirm = () => {
    setCode('')
    setCodeError(null)
    setConfirmOpen(true)
  }

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await saveSignupPolicy({
        mode,
        request_access: requestAccess,
        version: policy.version ?? 0,
        totp_code: code.trim(),
      })
      setConfirmOpen(false)
      toast.success('Sign-up policy saved')
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        // Wrong, reused or missing code: stay in the dialog.
        setCodeError(e.message)
        setCode('')
        return
      }
      setConfirmOpen(false)
      if (e instanceof AdminApiError && e.status === 409) {
        toast.error('Another administrator changed the policy. The latest value is shown.')
        onSaved()
        return
      }
      toast.error(e instanceof Error ? e.message : 'Could not save the sign-up policy')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Who can create an organization?</CardTitle>
          <CardDescription>
            Applies to every way in: email sign-up, Google, Microsoft and GitHub sign-in, and
            creating a team. Single sign-on into an existing organization is not affected.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <RadioGroup
            value={mode}
            onValueChange={(v) => setMode(v as Mode)}
            disabled={!canEdit}
            aria-label="Who can create an organization"
          >
            <div className="flex items-start gap-3">
              <RadioGroupItem value="admin_only" id={`${codeId}-admin`} className="mt-1" />
              <Label htmlFor={`${codeId}-admin`} className="grid gap-1 font-normal">
                <span className="font-medium">{MODE_LABEL.admin_only}</span>
                <span className="text-sm text-muted-foreground">
                  People sign in only to organizations you registered, through a membership, an
                  invitation or their organization&apos;s single sign-on. Anyone else sees
                  &quot;Your organization isn&apos;t set up yet&quot;, and no account is created for
                  them.
                </span>
              </Label>
            </div>
            <div className="flex items-start gap-3">
              <RadioGroupItem value="self_service" id={`${codeId}-self`} className="mt-1" />
              <Label htmlFor={`${codeId}-self`} className="grid gap-1 font-normal">
                <span className="font-medium">{MODE_LABEL.self_service}</span>
                <span className="text-sm text-muted-foreground">
                  Anyone may sign up and create their own organization.
                </span>
              </Label>
            </div>
          </RadioGroup>

          <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
            <Label htmlFor={`${codeId}-ra`} className="grid gap-1 font-normal">
              <span className="font-medium">Let people request access</span>
              <span className="text-sm text-muted-foreground">
                When only administrators create organizations, people who cannot sign in may ask for
                one. Requests wait for an administrator.
              </span>
            </Label>
            <Switch
              id={`${codeId}-ra`}
              checked={requestAccess}
              onCheckedChange={setRequestAccess}
              disabled={!canEdit}
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              Current: {MODE_LABEL[(policy.mode as Mode) ?? 'admin_only']},{' '}
              {SOURCE_LABEL[policy.source ?? 'default'] ?? policy.source}
              {policy.updated_at && (
                <>
                  , changed <RelativeTime date={policy.updated_at} className="text-xs" />
                </>
              )}
            </p>
            {canEdit && (
              <Button onClick={openConfirm} disabled={!dirty || busy}>
                Save
              </Button>
            )}
          </div>
          {!canEdit && (
            <p className="text-sm text-muted-foreground">Only a super admin can change it.</p>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        title="Change the sign-up policy?"
        desc={
          <div className="space-y-2">
            <p>
              New organizations: <strong>{MODE_LABEL[mode]}</strong>. Request access:{' '}
              <strong>{requestAccess ? 'on' : 'off'}</strong>.
            </p>
            <p>
              Existing organizations, users and sessions are not affected. The change is recorded in
              the admin audit log and the other administrators are emailed.
            </p>
          </div>
        }
        disabled={code.trim().length < 6}
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
        <div className="space-y-2">
          <Label htmlFor={codeId}>Code from your authenticator</Label>
          <Input
            id={codeId}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={8}
            aria-invalid={!!codeError}
          />
          {codeError && <p className="text-sm text-destructive">{codeError}</p>}
        </div>
      </ConfirmDialog>
    </>
  )
}
