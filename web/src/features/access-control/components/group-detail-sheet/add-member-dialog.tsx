import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Loader2, UserPlus } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { MemberRoleConfig, type GroupMemberRole } from '@/features/access-control'
import { MembershipEndFields } from './membership-end'

export interface NewGroupMember {
  userId: string
  role: GroupMemberRole
  /** YYYY-MM-DD, or "" for a membership with no end. */
  endsOn: string
  reason: string
}

interface AddMemberDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  newMember: NewGroupMember
  setNewMember: (member: NewGroupMember) => void
  /** An external team: every member needs an end date. */
  requireEnd: boolean
  isAddingMember: boolean
  onAddMember: () => void
  availableMembers: Array<{ user_id: string; name: string; email: string }>
}

export function AddMemberDialog({
  open,
  onOpenChange,
  newMember,
  setNewMember,
  isAddingMember,
  onAddMember,
  availableMembers,
  requireEnd,
}: AddMemberDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>Add Member</DialogTitle>
          <DialogDescription>Add a team member to this group.</DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Select Member</Label>
              <Select
                value={newMember.userId}
                onValueChange={(value) => setNewMember({ ...newMember, userId: value })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a member..." />
                </SelectTrigger>
                <SelectContent>
                  {availableMembers.length === 0 ? (
                    <SelectItem value="none" disabled>
                      All members are already in this group
                    </SelectItem>
                  ) : (
                    availableMembers.map((member) => (
                      <SelectItem key={member.user_id} value={member.user_id}>
                        {member.name} ({member.email})
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Role in Group</Label>
              <Select
                value={newMember.role}
                onValueChange={(value: GroupMemberRole) =>
                  setNewMember({ ...newMember, role: value })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(MemberRoleConfig).map(([role, config]) => (
                    <SelectItem key={role} value={role}>
                      <div className="flex items-center gap-2">
                        <Badge className={`${config.bgColor} ${config.color} border-0`}>
                          {config.label}
                        </Badge>
                        <span className="text-xs text-muted-foreground">{config.description}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <MembershipEndFields
              idPrefix="add-member"
              value={{ endsOn: newMember.endsOn, reason: newMember.reason }}
              onChange={(v) => setNewMember({ ...newMember, ...v })}
              required={requireEnd}
              disabled={isAddingMember}
            />
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={onAddMember}
            disabled={isAddingMember || !newMember.userId || (requireEnd && !newMember.endsOn)}
          >
            {isAddingMember ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <UserPlus className="me-2 h-4 w-4" />
            )}
            Add Member
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
