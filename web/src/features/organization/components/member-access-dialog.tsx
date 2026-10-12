'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { AlertCircle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { getErrorMessage } from '@/lib/api/error-handler'

import { updateMemberAccess } from '../api/use-members'
import {
  DEFAULT_EXTERNAL_ACCESS_DAYS,
  MAX_EXTERNAL_ACCESS_DAYS,
  dateInputDaysFromNow,
  endOfDayISO,
} from '../lib/external-access'
import type { MemberWithUser } from '../types/member.types'

/**
 * Change when an external member's access ends (api RFC-058). The date is
 * required unless another organization manages the address; the API caps it
 * at 365 days and re-enables a member whose access had ended.
 */
export function MemberAccessDialog({
  member,
  onOpenChange,
  onSaved,
}: {
  member: MemberWithUser | null
  onOpenChange: (open: boolean) => void
  onSaved?: () => void
}) {
  const [date, setDate] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const managed = !!member?.home_organization
  const min = dateInputDaysFromNow(1)
  const max = dateInputDaysFromNow(MAX_EXTERNAL_ACCESS_DAYS)

  useEffect(() => {
    if (!member) return
    setDate(
      member.access_expires_at
        ? member.access_expires_at.slice(0, 10)
        : dateInputDaysFromNow(DEFAULT_EXTERNAL_ACCESS_DAYS)
    )
    setReason('')
    setError(null)
  }, [member])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!member) return
    if (!date && !managed) {
      setError('Choose when access ends: no organization manages this address.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await updateMemberAccess(member.id, {
        expires_at: date ? endOfDayISO(date) : undefined,
        reason: reason.trim(),
      })
      toast.success(`Access of ${member.name || member.email} updated`)
      onSaved?.()
      onOpenChange(false)
    } catch (err) {
      setError(getErrorMessage(err, 'Could not change the end of access'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={!!member} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>Change end of access</DialogTitle>
            <DialogDescription>
              {member?.name || member?.email} is from outside the organization.
              {managed
                ? ` ${member?.home_organization} manages the address; their access also ends when they leave it.`
                : ' No organization manages the address, so their access must end.'}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="member-access-end">Access ends</Label>
                <Input
                  id="member-access-end"
                  type="date"
                  min={min}
                  max={max}
                  required={!managed}
                  value={date}
                  onChange={(e) => setDate(e.target.value)}
                  disabled={busy}
                />
                <p className="text-xs text-muted-foreground">
                  At most {MAX_EXTERNAL_ACCESS_DAYS} days from today. A member whose access ended is
                  enabled again.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="member-access-reason">Reason (optional)</Label>
                <Textarea
                  id="member-access-reason"
                  maxLength={500}
                  rows={2}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  disabled={busy}
                  placeholder="Engagement extended to the end of the quarter"
                />
              </div>
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
