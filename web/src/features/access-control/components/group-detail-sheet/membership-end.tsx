'use client'

/**
 * When a team membership ends (api RFC-050 W22). The API removes the
 * membership within a minute of its end date, so the member loses the team's
 * assets and roles; an external team needs an end date for every member.
 * Shared by the add-member dialog and the change-end-date dialog.
 */

import { useEffect, useState, type FormEvent } from 'react'
import { AlertCircle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  dateInputDaysFromNow,
  endOfDayISO,
  formatShortDate,
} from '@/features/organization/lib/external-access'
import { setGroupMemberExpiry } from '../../api/use-group-roles'

/** Longest team membership the API accepts. */
export const MAX_MEMBERSHIP_DAYS = 365
/** End date proposed for a member of an external team. */
export const DEFAULT_EXTERNAL_MEMBERSHIP_DAYS = 90

export interface MembershipEnd {
  /** YYYY-MM-DD, or "" for no end. */
  endsOn: string
  reason: string
}

/** The API body for an end date ("" is no end). */
export function membershipEndISO(endsOn: string): string | undefined {
  return endsOn ? endOfDayISO(endsOn) : undefined
}

export function MembershipEndFields({
  value,
  onChange,
  required,
  disabled,
  idPrefix,
}: {
  value: MembershipEnd
  onChange: (v: MembershipEnd) => void
  required: boolean
  disabled?: boolean
  idPrefix: string
}) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-ends`}>Membership ends{required ? '' : ' (optional)'}</Label>
        <Input
          id={`${idPrefix}-ends`}
          type="date"
          min={dateInputDaysFromNow(1)}
          max={dateInputDaysFromNow(MAX_MEMBERSHIP_DAYS)}
          required={required}
          value={value.endsOn}
          onChange={(e) => onChange({ ...value, endsOn: e.target.value })}
          disabled={disabled}
        />
        <p className="text-xs text-muted-foreground">
          {required
            ? 'This is an external team: every member needs an end date, at most a year ahead.'
            : 'Leave empty for a membership with no end. At most a year ahead.'}{' '}
          The member leaves the team, and loses its assets and roles, on that day.
        </p>
      </div>
      {value.endsOn && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-reason`}>Reason (optional)</Label>
          <Textarea
            id={`${idPrefix}-reason`}
            maxLength={500}
            rows={2}
            value={value.reason}
            onChange={(e) => onChange({ ...value, reason: e.target.value })}
            disabled={disabled}
            placeholder="Penetration test, fourth quarter"
          />
        </div>
      )}
    </>
  )
}

/** Change when one member's team membership ends. */
export function MembershipEndDialog({
  groupId,
  member,
  required,
  onOpenChange,
  onSaved,
}: {
  groupId: string
  member: { userId: string; name: string; expiresAt?: string } | null
  /** External teams: the end date cannot be cleared. */
  required: boolean
  onOpenChange: (open: boolean) => void
  onSaved?: () => void
}) {
  const [value, setValue] = useState<MembershipEnd>({ endsOn: '', reason: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!member) return
    setValue({ endsOn: member.expiresAt ? member.expiresAt.slice(0, 10) : '', reason: '' })
    setError(null)
  }, [member])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!member) return
    if (required && !value.endsOn) {
      setError('This is an external team: choose when the membership ends.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await setGroupMemberExpiry(groupId, member.userId, {
        expires_at: membershipEndISO(value.endsOn) ?? null,
        reason: value.reason.trim() || undefined,
      })
      toast.success(
        value.endsOn
          ? `${member.name} leaves the team on ${formatShortDate(endOfDayISO(value.endsOn))}`
          : `${member.name} stays in the team with no end date`
      )
      onSaved?.()
      onOpenChange(false)
    } catch (err) {
      setError(getErrorMessage(err, 'Could not change the end date'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={!!member} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>Change end date</DialogTitle>
            <DialogDescription>
              When {member?.name}&apos;s membership of this team ends.
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4 py-4">
              <MembershipEndFields
                idPrefix="membership-end"
                value={value}
                onChange={setValue}
                required={required}
                disabled={busy}
              />
              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
