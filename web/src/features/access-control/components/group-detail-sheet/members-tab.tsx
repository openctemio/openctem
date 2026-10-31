import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Users,
  UserPlus,
  Trash2,
  Crown,
  User,
  ChevronLeft,
  ChevronRight,
  CalendarClock,
  Globe,
} from 'lucide-react'
import { DataTableRowActions, EmptyState } from '@/features/shared'
import { MemberRoleConfig, getInitials, type GroupMember } from '@/features/access-control'
import { useState, useEffect } from 'react'
import { daysUntil, formatShortDate } from '@/features/organization/lib/external-access'
import { ListSearch } from '@/features/shared/components/list-search'

interface MembersTabProps {
  members: GroupMember[]
  totalCount: number
  isLoading: boolean
  limit: number
  offset: number
  onPageChange: (offset: number) => void
  /** Omitted when the caller may not add members (the button is hidden). */
  onAddMember?: () => void
  /** Omitted when the caller may not remove members (the action is hidden). */
  onRemoveMember?: (userId: string, name: string) => void
  /** Omitted when the caller may not change end dates (the action is hidden). */
  onChangeEnd?: (userId: string, name: string, expiresAt?: string) => void
  /** Show only members outside the organization and service accounts. */
  outsideOnly?: boolean
  onOutsideOnlyChange?: (on: boolean) => void
}

export function MembersTab({
  members,
  totalCount,
  isLoading,
  limit,
  offset,
  onPageChange,
  onAddMember,
  onRemoveMember,
  onChangeEnd,
  outsideOnly = false,
  onOutsideOnlyChange,
}: MembersTabProps) {
  const { t } = useTranslation()
  const [searchQuery, setSearchQuery] = useState('')

  // Reset to first page when search query changes
  useEffect(() => {
    if (searchQuery) {
      onPageChange(0)
    }
  }, [searchQuery, onPageChange])

  const hasOutside = members.some((m) => m.outside)
  const shown = outsideOnly ? members.filter((m) => m.outside) : members
  const filteredMembers = searchQuery
    ? shown.filter((member) => {
        const name = member.name || member.user_name || member.user?.name || ''
        const email = member.email || member.user_email || member.user?.email || ''
        return (
          name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          email.toLowerCase().includes(searchQuery.toLowerCase())
        )
      })
    : shown

  const currentPage = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(totalCount / limit)

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-sm font-medium">
          {t('org.teamMembers.heading', 'Members ({count})', { count: totalCount })}
        </h4>
        {onAddMember && (
          <Button size="sm" onClick={onAddMember}>
            <UserPlus className="me-2 h-4 w-4" />
            {t('org.teamMembers.add', 'Add member')}
          </Button>
        )}
      </div>

      <ListSearch
        className="mb-4"
        value={searchQuery}
        onChange={setSearchQuery}
        placeholder={t('org.teamMembers.search', 'Search members…')}
      />

      {(hasOutside || outsideOnly) && onOutsideOnlyChange && (
        <div className="mb-4">
          <Button
            size="sm"
            variant={outsideOnly ? 'secondary' : 'outline'}
            aria-pressed={outsideOnly}
            onClick={() => onOutsideOnlyChange(!outsideOnly)}
          >
            <Globe className="me-2 h-4 w-4" />
            {t('org.teamMembers.outsideOnly', 'Outside organization only')}
          </Button>
        </div>
      )}

      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : totalCount === 0 ? (
        <EmptyState
          icon={Users}
          title={t('org.teamMembers.empty', 'No members in this team yet')}
          card={false}
        />
      ) : filteredMembers.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <p>{t('org.teamMembers.noMatch', 'No member matches this search')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filteredMembers.map((member, index) => {
            const roleConfig = MemberRoleConfig[member.role] || MemberRoleConfig.member
            const name =
              member.name ||
              member.user_name ||
              member.user?.name ||
              t('org.teamMembers.unknown', 'Unknown member')
            const email = member.email || member.user_email || member.user?.email || ''
            const key = member.id || member.user_id || member.user?.id || `member-${index}`
            const initials = getInitials(name)

            return (
              <div
                key={key}
                className="flex items-center justify-between p-3 rounded-lg border hover:bg-muted/50 transition-colors"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <Avatar className="h-9 w-9 shrink-0">
                    <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                  </Avatar>
                  <div className="min-w-0">
                    <p className="text-sm font-medium break-words">{name}</p>
                    <p className="text-xs break-all text-muted-foreground">
                      {email}
                      {(member.added_by_name || member.added_by) && (
                        <span className="ms-2 text-xs text-muted-foreground/60">
                          {t('org.teamMembers.addedBy', 'Added by {name}', {
                            name: member.added_by_name || member.added_by || '',
                          })}
                        </span>
                      )}
                    </p>
                  </div>
                </div>
                <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
                  {member.outside && (
                    <Badge
                      variant="outline"
                      className="gap-1 text-xs"
                      data-testid="member-outside-badge"
                      title={t(
                        'org.teamMembers.outsideHint',
                        'Gets full data access only from a role given directly, never through a team'
                      )}
                    >
                      <Globe className="h-3 w-3" />
                      {member.service
                        ? t('org.teamMembers.service', 'Service account')
                        : t('org.teamMembers.outside', 'Outside organization')}
                    </Badge>
                  )}
                  {member.expires_at && (
                    <Badge
                      variant="outline"
                      className={
                        daysUntil(member.expires_at) <= 7
                          ? 'gap-1 border-warning/40 text-xs text-warning'
                          : 'gap-1 text-xs'
                      }
                      title={
                        t('org.teamMembers.leavesOn', 'Leaves the team {date}', {
                          date: formatShortDate(member.expires_at),
                        }) + (member.expiry_reason ? `: ${member.expiry_reason}` : '')
                      }
                    >
                      <CalendarClock className="h-3 w-3" />
                      {t('org.teamMembers.ends', 'Ends {date}', {
                        date: formatShortDate(member.expires_at),
                      })}
                    </Badge>
                  )}
                  <Badge variant="outline" className="text-xs">
                    {member.role === 'owner' && <Crown className="h-3 w-3 me-1" />}
                    {member.role === 'lead' && <Crown className="h-3 w-3 me-1" />}
                    {member.role === 'member' && <User className="h-3 w-3 me-1" />}
                    {roleConfig.label}
                  </Badge>
                  {(onRemoveMember || onChangeEnd) && (
                    <DataTableRowActions
                      actions={[
                        ...(onChangeEnd
                          ? [
                              {
                                label: t('org.teamMembers.changeEnd', 'Change end date'),
                                icon: CalendarClock,
                                onClick: () =>
                                  onChangeEnd(
                                    member.user_id || member.user?.id || '',
                                    name,
                                    member.expires_at
                                  ),
                              },
                            ]
                          : []),
                        ...(onRemoveMember
                          ? [
                              {
                                label: t('org.teamMembers.remove', 'Remove'),
                                icon: Trash2,
                                destructive: true,
                                onClick: () =>
                                  onRemoveMember(member.user_id || member.user?.id || '', name),
                              },
                            ]
                          : []),
                      ]}
                    />
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4 pt-4 border-t">
          <span className="text-xs text-muted-foreground">
            {t('org.teamMembers.page', 'Page {page} of {pages}', {
              page: currentPage,
              pages: totalPages,
            })}
          </span>
          <div className="flex items-center gap-1">
            <Button
              size="sm"
              variant="outline"
              disabled={offset === 0}
              aria-label={t('org.teamMembers.prev', 'Previous page')}
              onClick={() => onPageChange(Math.max(0, offset - limit))}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={offset + limit >= totalCount}
              aria-label={t('org.teamMembers.next', 'Next page')}
              onClick={() => onPageChange(offset + limit)}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
