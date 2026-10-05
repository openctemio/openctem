'use client'

/**
 * Offboarding wizard (RFC-050 member lifecycle). Shows what the member holds
 * and owns, asks for a new owner for every category of owned work, then
 * offboards: keys revoked, groups / grants / engagements / roles removed, the
 * membership kept as a tombstone. The backend re-checks everything (409
 * reassignment_required, 400 for a target that is not an active member).
 */

import { useMemo, useState } from 'react'
import { Loader2, UserMinus } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DetailCallout } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { offboardMember, useMemberAccessReport, useMembers } from '../api/use-members'
import type { MemberWithUser } from '../types/member.types'
import {
  FINDINGS_TO_QUEUE,
  OFFBOARD_CATEGORY_LABEL,
  type OffboardCategory,
  type OffboardPlanDraft,
  buildOffboardInput,
  missingReassignments,
  reassignCandidates,
  reassignmentConflict,
  requiredReassignments,
} from '../lib/member-lifecycle'
import { MemberAccessReportView } from './member-access-report'

export interface OffboardMemberDialogProps {
  tenantSlug: string | undefined
  /** The member to offboard; null closes the dialog. */
  member: MemberWithUser | null
  onOpenChange: (open: boolean) => void
  onOffboarded: () => void
}

const DRAFT_KEY: Record<OffboardCategory, keyof OffboardPlanDraft> = {
  schedules: 'schedulesTo',
  findings: 'findingsTo',
  assets: 'assetsTo',
}

export function OffboardMemberDialog({
  tenantSlug,
  member,
  onOpenChange,
  onOffboarded,
}: OffboardMemberDialogProps) {
  const open = !!member
  const { report, isLoading, mutate: reloadReport } = useMemberAccessReport(member?.id)
  // New owners come from the active members only (never a deactivated person).
  const { members } = useMembers(open ? tenantSlug : undefined, { status: 'active', limit: 500 })
  const [draft, setDraft] = useState<OffboardPlanDraft>({})
  const [submitting, setSubmitting] = useState(false)
  const [serverMissing, setServerMissing] = useState<OffboardCategory[]>([])

  const candidates = useMemo(
    () => (member ? reassignCandidates(members, member.user_id) : []),
    [members, member]
  )
  const required = report ? requiredReassignments(report) : []
  const missing = report ? missingReassignments(report, draft) : []
  const name = member ? member.name || member.email : ''

  const close = (next: boolean) => {
    if (submitting) return
    if (!next) {
      setDraft({})
      setServerMissing([])
    }
    onOpenChange(next)
  }

  const submit = async () => {
    if (!member || !report) return
    setSubmitting(true)
    setServerMissing([])
    try {
      const res = await offboardMember(member.id, buildOffboardInput(report, draft))
      toast.success(
        `${name} offboarded: ${res.revoked_keys} key(s) revoked, ${res.removed_groups} group(s) removed`
      )
      setDraft({})
      onOpenChange(false)
      onOffboarded()
    } catch (error) {
      const conflict = reassignmentConflict(error)
      if (conflict) {
        // Their holdings changed since the report loaded: show it again.
        setServerMissing(conflict)
        void reloadReport()
      } else {
        toast.error(getErrorMessage(error, 'Failed to offboard member'))
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Offboard {name}?</DialogTitle>
          <DialogDescription>
            Their access ends permanently: API keys are revoked and their access groups, grants,
            pentest engagements and roles are removed. Their membership stays as a record so history
            keeps their name; inviting them again later starts from zero. To pause access instead,
            disable them.
          </DialogDescription>
        </DialogHeader>

        <MemberAccessReportView report={report} isLoading={isLoading} />

        {report && required.length > 0 && (
          <div className="space-y-4 border-t pt-4" data-testid="offboard-reassignment">
            <p className="text-sm font-medium">Hand their work to someone else</p>
            {required.map((category) => {
              const key = DRAFT_KEY[category]
              const id = `offboard-${category}`
              return (
                <div key={category} className="grid gap-1.5">
                  <Label htmlFor={id}>{OFFBOARD_CATEGORY_LABEL[category]}</Label>
                  <Select
                    value={draft[key] ?? ''}
                    onValueChange={(v) => setDraft((d) => ({ ...d, [key]: v }))}
                  >
                    <SelectTrigger id={id} aria-label={OFFBOARD_CATEGORY_LABEL[category]}>
                      <SelectValue placeholder="Choose a new owner" />
                    </SelectTrigger>
                    <SelectContent>
                      {category === 'findings' && (
                        <SelectItem value={FINDINGS_TO_QUEUE}>
                          Return to the queue (unassigned)
                        </SelectItem>
                      )}
                      {candidates.map((c) => (
                        <SelectItem key={c.user_id} value={c.user_id}>
                          {c.name || c.email}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )
            })}
          </div>
        )}

        {serverMissing.length > 0 && (
          <DetailCallout tone="warning" title="Something still needs a new owner">
            {serverMissing.map((c) => OFFBOARD_CATEGORY_LABEL[c]).join(', ')}. Their holdings changed
            while this dialog was open; choose a new owner and try again.
          </DetailCallout>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => close(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() => void submit()}
            disabled={submitting || isLoading || !report || missing.length > 0}
          >
            {submitting ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <UserMinus className="me-2 h-4 w-4" />
            )}
            Offboard
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
