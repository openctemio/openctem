'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { ChevronDown, User, Loader2, Check, UserPlus } from 'lucide-react'
import { useTenant } from '@/context/tenant-provider'
import { useMembers } from '@/features/organization/api/use-members'
import { useAssignableMembers } from '../api/use-assignable-members'
import { useSearchQuery } from '@/hooks/use-search-query'

// Max members to display in dropdown
const MAX_DISPLAY_MEMBERS = 5

export interface AssigneeUser {
  id: string
  name: string
  email?: string
  role?: string
}

interface AssigneeSelectProps {
  /** Current assignee */
  value?: AssigneeUser | null
  /** Called when assignee changes */
  onChange: (user: AssigneeUser | null) => void
  /** Whether the select is disabled */
  disabled?: boolean
  /** Show loading spinner (for external API calls) */
  loading?: boolean
  /** Button size variant */
  size?: 'sm' | 'default'
  /** Button variant */
  variant?: 'outline' | 'ghost'
  /** Show full name or truncated */
  showFullName?: boolean
  /** Custom placeholder when no assignee */
  placeholder?: string
  /**
   * The finding being assigned. The list is then the members who can read
   * it (server-side), never every member. Without it (bulk assignment) the
   * server refuses the unreadable ones per finding.
   */
  findingId?: string
}

function getInitials(name: string): string {
  return name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

export function AssigneeSelect({
  value,
  onChange,
  disabled = false,
  loading = false,
  size = 'sm',
  variant = 'outline',
  showFullName = false,
  placeholder,
  findingId,
}: AssigneeSelectProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const { currentTenant } = useTenant()

  // Debounce search to reduce API calls
  const deferredSearch = useSearchQuery(search).term

  // Lazy fetch: only load members when the popover is opened. One finding:
  // the server lists who can read it; bulk: the plain member list.
  const isSearchActive = deferredSearch.length > 0
  const scoped = Boolean(findingId)
  const {
    members: dropdownMembers,
    total: dropdownTotal,
    isLoading: isLoadingDropdown,
  } = useMembers(open && !scoped ? currentTenant?.id : undefined, {
    limit: MAX_DISPLAY_MEMBERS,
  })
  const {
    members: searchedMembers,
    total: searchedTotal,
    isLoading: isSearching,
  } = useMembers(open && !scoped && isSearchActive ? currentTenant?.id : undefined, {
    search: deferredSearch,
    limit: MAX_DISPLAY_MEMBERS,
  })
  const { members: assignable, isLoading: isLoadingAssignable } = useAssignableMembers(findingId, {
    search: deferredSearch,
    limit: 20,
    enabled: open,
  })

  const displayMembers = scoped ? assignable : isSearchActive ? searchedMembers : dropdownMembers
  const totalMembers = scoped ? assignable.length : isSearchActive ? searchedTotal : dropdownTotal
  const isLoadingMembers = scoped
    ? isLoadingAssignable
    : isSearchActive
      ? isSearching
      : isLoadingDropdown

  // Check if there are more members than displayed
  const hasMoreMembers = scoped ? totalMembers >= 20 : totalMembers > MAX_DISPLAY_MEMBERS

  const handleSelect = (member: { user_id: string; name?: string; email?: string }) => {
    onChange({
      id: member.user_id,
      name: member.name || t('findings.assigneeSelect.unknown', 'Unknown'),
      email: member.email,
    })
    setOpen(false)
    setSearch('')
  }

  const handleUnassign = () => {
    onChange(null)
    setOpen(false)
    setSearch('')
  }

  return (
    <Popover
      open={open}
      onOpenChange={(isOpen) => {
        setOpen(isOpen)
        if (!isOpen) setSearch('')
      }}
    >
      <PopoverTrigger asChild>
        <Button
          variant={variant}
          size={size}
          className={`${size === 'sm' ? 'h-7 px-1.5 gap-1 text-xs' : 'h-9 sm:h-8 gap-2'} min-h-[32px]`}
          disabled={disabled || loading}
        >
          {loading && <Loader2 className="h-3 w-3 animate-spin" />}
          {!loading && value ? (
            // Show assignee info - if name is empty (not enriched), show "Assigned" with user icon
            value.name ? (
              <>
                <Avatar className="h-4 w-4">
                  <AvatarFallback className="text-[8px]">{getInitials(value.name)}</AvatarFallback>
                </Avatar>
                <span className="max-w-[80px] truncate">
                  {showFullName ? value.name : value.name.split(' ')[0]}
                </span>
              </>
            ) : (
              // Assigned but name not loaded yet - show placeholder
              <>
                <User className="h-3 w-3" />
                <span className="text-muted-foreground hidden sm:inline">
                  {t('findings.assigneeSelect.assigned', 'Assigned')}
                </span>
              </>
            )
          ) : !loading ? (
            <>
              <UserPlus className="h-3 w-3" />
              <span className="sr-only sm:not-sr-only">
                {placeholder ?? t('findings.assigneeSelect.assign', 'Assign')}
              </span>
            </>
          ) : null}
          {!disabled && <ChevronDown className="h-3 w-3" />}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-56 p-0" align="start">
        <Command shouldFilter={false}>
          <CommandInput
            placeholder={t('findings.assigneeSelect.search', 'Search members...')}
            value={search}
            onValueChange={setSearch}
          />
          <CommandList>
            {isLoadingMembers && (
              <div className="flex items-center justify-center py-4">
                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
              </div>
            )}
            {!isLoadingMembers && displayMembers.length === 0 && (
              <CommandEmpty>
                {t('findings.assigneeSelect.noMembers', 'No members found.')}
              </CommandEmpty>
            )}
            {!isLoadingMembers && (
              <>
                {value && !search && (
                  <>
                    <CommandGroup>
                      <CommandItem onSelect={handleUnassign} className="text-muted-foreground">
                        <User className="me-2 h-4 w-4" />
                        {t('findings.assigneeSelect.unassign', 'Unassign')}
                      </CommandItem>
                    </CommandGroup>
                    <CommandSeparator />
                  </>
                )}
                {displayMembers.length > 0 && (
                  <CommandGroup
                    heading={
                      hasMoreMembers
                        ? t(
                            'findings.assigneeSelect.teamMembersTotal',
                            'Team Members ({total} total)',
                            {
                              total: totalMembers,
                            }
                          )
                        : t('findings.assigneeSelect.teamMembers', 'Team Members')
                    }
                  >
                    {displayMembers.map((member) => (
                      <CommandItem
                        key={member.user_id}
                        value={member.user_id}
                        onSelect={() => handleSelect(member)}
                        className="flex items-center gap-2"
                      >
                        <Avatar className="h-5 w-5 shrink-0">
                          <AvatarFallback className="text-[10px]">
                            {getInitials(member.name || 'U')}
                          </AvatarFallback>
                        </Avatar>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="truncate">
                              {member.name || t('findings.assigneeSelect.unknown', 'Unknown')}
                            </span>
                            {member.role && (
                              <span className="text-[10px] text-muted-foreground bg-muted px-1 py-0.5 rounded capitalize shrink-0">
                                {member.role}
                              </span>
                            )}
                          </div>
                          {member.email && (
                            <div className="text-xs text-muted-foreground truncate">
                              {member.email}
                            </div>
                          )}
                        </div>
                        {value?.id === member.user_id && (
                          <Check className="h-4 w-4 text-primary shrink-0" />
                        )}
                      </CommandItem>
                    ))}
                  </CommandGroup>
                )}
                {hasMoreMembers && (
                  <div className="px-2 py-1.5 text-xs text-muted-foreground text-center">
                    {t('findings.assigneeSelect.typeToSearch', 'Type to search for more members')}
                  </div>
                )}
              </>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
