'use client'

import type { ReactNode } from 'react'

import { useState, useCallback, useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  FacetOption,
  FacetPanel,
  FacetSection,
  FilterSheet,
} from '@/features/shared'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { toast } from 'sonner'
import { Plus, Trash2, Eye, Pencil, Loader2, FolderKey } from 'lucide-react'
import { useSWRConfig } from 'swr'
import {
  useGroups,
  useCreateGroup,
  useDeleteGroup,
  type Group,
  generateSlug,
} from '@/features/access-control'
import type { GroupType } from '@/features/access-control/types/group.types'
import { GroupDetailSheet } from '@/features/access-control/components/group-detail-sheet'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, useCanMutate, usePermissions } from '@/lib/permissions'
import { setTeamAccess, useTeamPresetTemplates } from '../api/use-team-access'
import { EMPTY_TEAM_ACCESS, TeamAccessFields, type TeamAccessValue } from './team-access-fields'
import { confirmName } from '@/lib/confirm-name'
import { toDisplayText } from '@/lib/untrusted-text'
import { replaceUrlSearch, useUrlFilter } from '@/hooks/use-url-param'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

const KINDS: GroupType[] = ['team', 'security_team', 'department', 'project', 'external']

const teamHref = (id: string) => `/settings/teams?team=${encodeURIComponent(id)}`

export interface SectionProps {
  /**
   * The page frame around this section's list: it gets the section's header
   * actions (its Create button) and its content, so the page keeps one header
   * and one set of tabs while each section keeps its own dialogs and state.
   */
  frame: (actions: ReactNode, content: ReactNode, readOnly: boolean) => ReactNode
}

/**
 * The Teams tab of /settings/teams (board P4-Settings-Teams): search, Add
 * filter (kind) and Display; columns Team, Kind, Members, Assets; the team
 * name is a link that opens its detail (`?team=<id>`). The list is small and
 * unpaged, so the filters apply on the client.
 */
export function TeamsSection({ frame }: SectionProps) {
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()

  const { groups, isLoading, isError, error, mutate: mutateGroups } = useGroups()
  const { createGroup, isCreating } = useCreateGroup()

  const [teamParam, setTeamParam] = useUrlFilter('team', '')
  const openTeam = useCallback((id: string | null) => setTeamParam(id ?? ''), [setTeamParam])
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [groupToDelete, setGroupToDelete] = useState<Group | null>(null)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const [kindParam, setKindParam] = useUrlFilter('kind', '')
  const kind = (KINDS as string[]).includes(kindParam) ? (kindParam as GroupType) : null
  const [createForm, setCreateForm] = useState({
    name: '',
    description: '',
  })
  const [createAccess, setCreateAccess] = useState<TeamAccessValue>(EMPTY_TEAM_ACCESS)
  // The Access section follows the route that sets it, so a person who cannot
  // set access is not offered it.
  const canSetAccess = useCanMutate('PUT /api/v1/groups/{groupId}/access')
  const canCreate = useCanMutate('POST /api/v1/groups')
  const { isOwner } = usePermissions()
  const { templates: presetTemplates, isLoading: presetsLoading } = useTeamPresetTemplates({
    skip: !createDialogOpen || !canSetAccess,
  })

  const { deleteGroup, isDeleting } = useDeleteGroup(groupToDelete?.id || null)

  const refreshData = useCallback(() => {
    void mutateGroups()
  }, [mutateGroups])

  const kindLabel = useCallback(
    (k: GroupType | undefined) => t(`org.teamSheet.type.${k ?? 'team'}`),
    [t]
  )

  const shown = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return groups.filter((g) => {
      if (kind && (g.group_type ?? g.type ?? 'team') !== kind) return false
      if (!q) return true
      return g.name.toLowerCase().includes(q) || !!g.description?.toLowerCase().includes(q)
    })
  }, [groups, kind, searchQuery])

  // A row menu only where it offers a change (an overflow menu never holds
  // one item): a reader opens the team by its name or the row.
  const canEditTeam = useCanMutate('PUT /api/v1/groups/{groupId}')
  const canDeleteTeam = useCanMutate('DELETE /api/v1/groups/{groupId}')
  const teamMenu = useCallback(
    (group: Group) => {
      if (!(canEditTeam || canDeleteTeam)) return null
      const name = toDisplayText(group.name, 120)
      return (
        <DataTableRowActions
          title={name}
          label={t('common.rowActions.actionsFor', 'Actions for {name}', { name })}
          actions={[
            {
              label: t('org.teams.viewDetails', 'View details'),
              icon: Eye,
              onClick: () => openTeam(group.id),
            },
            {
              label: t('org.teams.editTeam', 'Edit team'),
              icon: Pencil,
              route: 'PUT /api/v1/groups/{groupId}',
              onClick: () => openTeam(group.id),
            },
            {
              label: t('org.teams.deleteTeam', 'Delete team'),
              icon: Trash2,
              destructive: true,
              separatorBefore: true,
              // Owner only on the API (RequireOwner), so admins do not see it.
              route: 'DELETE /api/v1/groups/{groupId}',
              onClick: () => setGroupToDelete(group),
            },
          ]}
        />
      )
    },
    [t, openTeam, canEditTeam, canDeleteTeam]
  )

  const teamLabel = t('org.teams.col.team', 'Team')
  const kindColLabel = t('org.teams.col.kind', 'Kind')
  const membersLabel = t('org.teams.col.members', 'Members')
  const assetsLabel = t('org.teams.col.assets', 'Assets')

  const columns: ColumnDef<Group>[] = [
    {
      accessorKey: 'name',
      meta: { kind: 'name', pin: 'start', minWidth: 220, label: teamLabel },
      enableHiding: false,
      header: ({ column }) => <DataTableColumnHeader column={column} title={teamLabel} />,
      cell: ({ row }) => {
        const g = row.original
        const name = toDisplayText(g.name, 200)
        return (
          <div className="min-w-0">
            <RowNameLink
              href={teamHref(g.id)}
              onOpen={() => openTeam(g.id)}
              title={name}
              className="block"
            >
              {name}
            </RowNameLink>
            {g.description && (
              <p className="text-cap text-muted-foreground truncate">
                {toDisplayText(g.description, 300)}
              </p>
            )}
          </div>
        )
      },
    },
    {
      id: 'kind',
      accessorFn: (g) => g.group_type ?? g.type ?? 'team',
      meta: { kind: 'status', width: 148, label: kindColLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={kindColLabel} />,
      cell: ({ row }) => (
        <Badge variant="outline">{kindLabel(row.original.group_type ?? row.original.type)}</Badge>
      ),
    },
    {
      id: 'members',
      accessorFn: (g) => g.member_count ?? 0,
      meta: { kind: 'number', label: membersLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={membersLabel} />,
      cell: ({ row }) => <span className="tabular-nums">{row.original.member_count ?? 0}</span>,
    },
    {
      id: 'assets',
      accessorFn: (g) => g.asset_count ?? 0,
      meta: { kind: 'number', label: assetsLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={assetsLabel} />,
      cell: ({ row }) => <span className="tabular-nums">{row.original.asset_count ?? 0}</span>,
    },
    {
      id: 'actions',
      meta: { kind: 'actions' },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => teamMenu(row.original),
    },
  ]

  const handleCreateGroup = async () => {
    if (!createForm.name) {
      toast.error(t('org.teams.nameRequired', 'Enter a team name'))
      return
    }

    try {
      const created = await createGroup({
        slug: generateSlug(createForm.name),
        name: createForm.name,
        description: createForm.description || undefined,
        group_type: 'team', // Default type for data scoping groups
      })
      toast.success(t('org.teams.created', 'Team "{name}" created', { name: createForm.name }))
      setCreateDialogOpen(false)
      setCreateForm({ name: '', description: '' })
      refreshData()
      // The team exists even if its access cannot be set: say so and leave the
      // rest to the team's Access tab.
      const createdId = (created as unknown as { id?: string } | undefined)?.id
      if (createdId && (createAccess.presets.length > 0 || createAccess.scopeMode !== 'specific')) {
        try {
          await setTeamAccess(createdId, {
            presets: createAccess.presets,
            scope_mode: createAccess.scopeMode,
          })
        } catch (accessError) {
          toast.error(
            getErrorMessage(
              accessError,
              t(
                'org.teams.accessFailed',
                'The team was created but its access was not saved. Set it on the team.'
              )
            )
          )
        }
      }
      setCreateAccess(EMPTY_TEAM_ACCESS)
    } catch (err) {
      toast.error(getErrorMessage(err, t('org.teams.createFailed', 'Failed to create team')))
    }
  }

  const handleDeleteGroup = async () => {
    if (!groupToDelete) return

    try {
      await deleteGroup()
      toast.success(
        t('org.teams.deleted', 'Team "{name}" deleted', {
          name: toDisplayText(groupToDelete.name, 120),
        })
      )
      setGroupToDelete(null)
      void mutate(
        (key: string) => typeof key === 'string' && key.startsWith('/api/v1/groups'),
        undefined,
        { revalidate: true }
      )
      refreshData()
    } catch (err) {
      // The dialog stays open: the team is still there.
      toast.error(getErrorMessage(err, t('org.teams.deleteFailed', 'Failed to delete team')))
    }
  }

  const clearFilters = () => {
    const next = new URLSearchParams(window.location.search)
    for (const name of ['kind', 'q']) next.delete(name)
    replaceUrlSearch(next)
  }
  const chipText = kind ? t('org.teams.chip.kind', 'Kind: {value}', { value: kindLabel(kind) }) : ''
  const chipsRow = kind ? (
    <FilterChipsRow
      data-testid="teams-filter-chips"
      label={t('common.filterChips.label', 'Active filters')}
      chips={[
        <RemovableFilterChip
          key="kind"
          text={chipText}
          onRemove={() => setKindParam('')}
          removeLabel={t('org.teams.chip.remove', 'Remove filter {filter}', { filter: chipText })}
        />,
      ]}
    />
  ) : undefined
  const facets = (
    <FacetPanel activeCount={kind ? 1 : 0} onClearAll={() => setKindParam('')}>
      <FacetSection title={kindColLabel} selectedCount={kind ? 1 : 0}>
        {KINDS.map((k) => (
          <FacetOption
            key={k}
            label={kindLabel(k)}
            checked={kind === k}
            onCheckedChange={(on) => setKindParam(on ? k : '')}
          />
        ))}
      </FacetSection>
    </FacetPanel>
  )
  const filtersLabel = t('org.teams.filtersLabel', 'Team filters')
  const deleteMembers = groupToDelete?.member_count
  const deleteAssets = groupToDelete?.asset_count

  const createButton = (
    <Button onClick={() => setCreateDialogOpen(true)}>
      <Plus aria-hidden />
      {t('org.teams.createTeam', 'Create team')}
    </Button>
  )

  const content = (
    <>
      <DataTable
        columns={columns}
        data={shown}
        getRowId={(g) => g.id}
        isLoading={isLoading && groups.length === 0}
        error={isError ? (error ?? true) : undefined}
        onRetry={refreshData}
        errorTitle={t('org.teams.subject', 'teams')}
        showSearch={false}
        search={{
          value: searchQuery,
          onChange: setSearchQuery,
          placeholder: t('org.teams.searchPlaceholder', 'Search teams…'),
          label: t('org.teams.searchLabel', 'Search teams'),
        }}
        filterToggle={{
          open: false,
          onToggle: () => setFilterSheetOpen(true),
          onOpenSheet: () => setFilterSheetOpen(true),
          activeCount: kind ? 1 : 0,
          controlsId: 'team-filters',
          label: filtersLabel,
          sheetOnly: true,
        }}
        toolbarStart={<AddFilterPanel>{facets}</AddFilterPanel>}
        toolbarBelow={chipsRow}
        showToolbar={groups.length > 0 || isError}
        onRowClick={(g) => openTeam(g.id)}
        showPagination={shown.length > 25}
        paginationNoun={t('org.teams.noun', 'teams')}
        mobileRow={(g) => (
          <PersonPhoneCard
            title={toDisplayText(g.name, 200)}
            address={g.description ? toDisplayText(g.description, 300) : undefined}
            onOpen={() => openTeam(g.id)}
            menu={teamMenu(g)}
            facts={
              <>
                <Badge variant="outline">{kindLabel(g.group_type ?? g.type)}</Badge>
                <span className="text-cap text-muted-foreground tabular-nums">
                  {t(
                    'org.teams.card.counts',
                    '{members, plural, one {# member} other {# members}}, {assets, plural, one {# asset} other {# assets}}',
                    { members: g.member_count ?? 0, assets: g.asset_count ?? 0 }
                  )}
                </span>
              </>
            }
          />
        )}
        isFiltered={!!kind || searchQuery.trim() !== ''}
        onClearFilters={clearFilters}
        emptyState={{
          nothingYet: (
            <EmptyState
              icon={FolderKey}
              title={t('org.teams.emptyTitle', 'No teams yet')}
              // The header's Create team is the page's one main action, so the
              // empty state points to it in words instead of repeating it.
              description={
                canCreate
                  ? t(
                      'org.teams.emptyBody',
                      'Teams decide which assets their members see. Use Create team above to add one for each group that owns systems.'
                    )
                  : t(
                      'org.teams.emptyBodyAsk',
                      'Teams decide which assets their members see. Ask an owner or administrator to create one.'
                    )
              }
            />
          ),
          noMatch: {
            title: t('org.teams.noMatch', 'No teams match these filters'),
            hint: t('org.teams.noMatchHint', 'Try removing a filter or clearing the search.'),
          },
        }}
      />

      {/* Members in no team see nothing (owner decision D2); there is
          no per-organization "see everything" switch. */}
      <p className="max-w-prose text-body text-muted-foreground" data-testid="no-team-access-note">
        {t(
          'org.teams.noTeamNote',
          'Members who are in no team see no assets or findings until you add them to a team or grant them an asset. Owners, admins and roles with full data access see everything.'
        )}
      </p>
    </>
  )

  return (
    <>
      {frame(<Can route="POST /api/v1/groups">{createButton}</Can>, content, !canCreate)}

      <FilterSheet open={filterSheetOpen} onOpenChange={setFilterSheetOpen} title={filtersLabel}>
        {facets}
      </FilterSheet>

      <GroupDetailSheet
        groupId={teamParam || null}
        open={!!teamParam}
        onOpenChange={(open) => !open && openTeam(null)}
        onUpdate={refreshData}
        onCreateTeam={() => setCreateDialogOpen(true)}
      />

      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('org.teams.createTeam', 'Create team')}</DialogTitle>
            <DialogDescription>
              {t(
                'org.teams.createDesc',
                'Create a new team to organize users and control access to assets.'
              )}
            </DialogDescription>
          </DialogHeader>

          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="group-name">{t('org.teams.teamName', 'Team name')}</Label>
                <Input
                  id="group-name"
                  placeholder={t('org.teams.teamNamePlaceholder', 'e.g., Security team, DevOps')}
                  value={createForm.name}
                  onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="group-description">
                  {t('org.teams.descLabel', 'Description (optional)')}
                </Label>
                <Textarea
                  id="group-description"
                  placeholder={t('org.teams.descPlaceholder', 'What this team is for')}
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  rows={3}
                />
              </div>

              {canSetAccess && (
                <div className="space-y-2 border-t pt-4">
                  <h3 className="text-body font-semibold">{t('org.teamAccess.title', 'Access')}</h3>
                  <TeamAccessFields
                    idPrefix="create-team"
                    templates={presetTemplates}
                    loading={presetsLoading}
                    value={createAccess}
                    onChange={setCreateAccess}
                    canSetAllAssets={isOwner()}
                    disabled={isCreating}
                  />
                </div>
              )}
            </div>
          </DialogBody>

          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreateGroup} disabled={isCreating || !createForm.name}>
              {isCreating ? <Loader2 className="animate-spin" aria-hidden /> : <Plus aria-hidden />}
              {t('org.teams.createTeam', 'Create team')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!groupToDelete}
        onOpenChange={(open) => {
          if (!open) setGroupToDelete(null)
        }}
        destructive
        title={t('confirm.team.deleteTitle', 'Delete the team "{name}"?', {
          name: groupToDelete ? toDisplayText(groupToDelete.name, 120) : '',
        })}
        desc={
          deleteMembers === undefined && deleteAssets === undefined
            ? t(
                'confirm.team.deleteDesc',
                'Members lose the access this team gives them, including to assets the team owns. This cannot be undone.'
              )
            : t(
                'confirm.team.deleteImpact',
                '{members, plural, one {# member loses} other {# members lose}} the access this team gives them, including to its {assets, plural, one {# asset} other {# assets}}, unless another team or grant covers them. This cannot be undone.',
                { members: deleteMembers ?? 0, assets: deleteAssets ?? 0 }
              )
        }
        confirmText={
          <>
            {isDeleting ? <Loader2 className="animate-spin" aria-hidden /> : <Trash2 aria-hidden />}
            {t('confirm.team.delete', 'Delete team')}
          </>
        }
        isLoading={isDeleting}
        typeToConfirm={
          groupToDelete ? confirmName(groupToDelete.name, groupToDelete.id) : undefined
        }
        handleConfirm={handleDeleteGroup}
      />
    </>
  )
}
