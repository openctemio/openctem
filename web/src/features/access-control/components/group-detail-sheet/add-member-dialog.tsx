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
import { useTranslation } from '@/context/i18n-provider'

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
  availableMembers: Array<{ user_id: string; name: string; email: string; kind?: string }>
  /**
   * The team carries a full-data role: people outside the organization are
   * listed but cannot be chosen (the API refuses them, TEAM_EXTERNAL_FULL_DATA).
   */
  carriesFullData?: boolean
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
  carriesFullData = false,
}: AddMemberDialogProps) {
  const { t } = useTranslation()
  const blocked = (m: { kind?: string }) => carriesFullData && m.kind === 'external'
  const anyBlocked = availableMembers.some(blocked)
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('org.teamAddMember.title', 'Add member')}</DialogTitle>
          <DialogDescription>
            {t('org.teamAddMember.desc', 'Add someone from your organization to this team.')}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="add-member-user">{t('org.teamAddMember.member', 'Member')}</Label>
              <Select
                value={newMember.userId}
                onValueChange={(value) => setNewMember({ ...newMember, userId: value })}
              >
                <SelectTrigger id="add-member-user">
                  <SelectValue placeholder={t('org.teamAddMember.choose', 'Choose a member…')} />
                </SelectTrigger>
                <SelectContent>
                  {availableMembers.length === 0 ? (
                    <SelectItem value="none" disabled>
                      {t('org.teamAddMember.allIn', 'Everyone is already in this team')}
                    </SelectItem>
                  ) : (
                    availableMembers.map((member) => (
                      <SelectItem
                        key={member.user_id}
                        value={member.user_id}
                        disabled={blocked(member)}
                      >
                        {member.name} ({member.email})
                        {blocked(member) && (
                          <span className="ms-2 text-xs text-muted-foreground">
                            {t('org.teamAddMember.outside', 'Outside organization')}
                          </span>
                        )}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
              {anyBlocked && (
                <p className="text-xs text-muted-foreground" data-testid="add-member-outside-note">
                  {t(
                    'org.teamAddMember.outsideNote',
                    'This team gives full data access, so people outside your organization cannot join it. Give them a role directly instead.'
                  )}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label>{t('org.teamAddMember.role', 'Role in the team')}</Label>
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
            {t('common.cancel', 'Cancel')}
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
            {t('org.teamAddMember.submit', 'Add member')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
