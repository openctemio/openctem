'use client'

import { useState, useCallback, useEffect } from 'react'
import { devLog } from '@/lib/logger'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { TabsCount } from '@/components/ui/tabs'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { Hash, Loader2, Pencil, Save, ShieldCheck, Trash2, Users } from 'lucide-react'
import {
  useGroup,
  useGroupMembers,
  useGroupAssets,
  useUpdateGroup,
  useAddGroupMember,
  useRemoveGroupMember,
  useAssignAssetToGroup,
  useUnassignAssetFromGroup,
  type GroupMemberRole,
  formatDate,
  getGroupType,
  GroupTypeConfig,
} from '@/features/access-control'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  DetailTabs,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import { useMembers } from '@/features/organization'
import { useTenant } from '@/context/tenant-provider'

import {
  MembersTab,
  AssetsTab,
  ScopeRulesTab,
  ErrorDisplay,
  AddMemberDialog,
  AddAssetDialog,
  BulkAddAssetsDialog,
} from './group-detail-sheet/index'

type GroupTab = 'overview' | 'members' | 'assets' | 'scope-rules'

interface GroupDetailSheetProps {
  groupId: string | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onUpdate?: () => void
}

export function GroupDetailSheet({ groupId, open, onOpenChange, onUpdate }: GroupDetailSheetProps) {
  const { currentTenant } = useTenant()
  const tenantSlug = currentTenant?.slug

  // Pagination state
  const [membersOffset, setMembersOffset] = useState(0)
  const [assetsOffset, setAssetsOffset] = useState(0)
  const PAGE_SIZE = 20

  // API Hooks - Only fetch when sheet is open (avoid unnecessary API calls)
  const {
    group,
    isLoading: groupLoading,
    isError: groupError,
    error: groupErrorDetails,
    mutate: mutateGroup,
  } = useGroup(groupId, { skip: !open })
  const {
    members,
    totalCount: membersTotalCount,
    isLoading: membersLoading,
    mutate: mutateMembers,
  } = useGroupMembers(groupId, { skip: !open, limit: PAGE_SIZE, offset: membersOffset })
  const { updateGroup, isUpdating } = useUpdateGroup(open ? groupId : null)
  const { addMember, isAdding: isAddingMember } = useAddGroupMember(open ? groupId : null)
  const { members: tenantMembers } = useMembers(open ? tenantSlug : undefined)
  const {
    assets,
    totalCount: assetsTotalCount,
    isLoading: assetsLoading,
    mutate: mutateAssets,
  } = useGroupAssets(groupId, { skip: !open, limit: PAGE_SIZE, offset: assetsOffset })
  const { assignAsset, isAssigning: isAssigningAsset } = useAssignAssetToGroup(
    open ? groupId : null
  )

  // UI State
  const [activeTab, setActiveTab] = useState<GroupTab>('overview')
  const [isEditing, setIsEditing] = useState(false)
  const [editForm, setEditForm] = useState({ name: '', description: '' })
  const [addMemberDialogOpen, setAddMemberDialogOpen] = useState(false)
  const [addAssetDialogOpen, setAddAssetDialogOpen] = useState(false)
  const [bulkAddAssetsDialogOpen, setBulkAddAssetsDialogOpen] = useState(false)
  const [memberToRemove, setMemberToRemove] = useState<{ userId: string; name: string } | null>(
    null
  )
  const [assetToRemove, setAssetToRemove] = useState<{ id: string; name: string } | null>(null)
  const [newMember, setNewMember] = useState({ userId: '', role: 'member' as GroupMemberRole })

  // Remove hooks
  const { removeMember, isRemoving: isRemovingMember } = useRemoveGroupMember(
    groupId,
    memberToRemove?.userId || null
  )
  const { unassignAsset, isUnassigning: isUnassigningAsset } = useUnassignAssetFromGroup(
    groupId,
    assetToRemove?.id || null
  )

  // Reset pagination and revalidate when sheet opens
  useEffect(() => {
    if (open && groupId) {
      setMembersOffset(0)
      setAssetsOffset(0)
      setActiveTab('overview')
      setIsEditing(false)
      mutateGroup()
      mutateMembers()
      mutateAssets()
    }
  }, [open, groupId, mutateGroup, mutateMembers, mutateAssets])

  // Log errors for debugging
  useEffect(() => {
    if (groupError && groupErrorDetails) {
      devLog.error('[GroupDetailSheet] Failed to load group:', {
        groupId,
        error: groupErrorDetails,
        timestamp: new Date().toISOString(),
      })
    }
  }, [groupError, groupErrorDetails, groupId])

  // Start editing
  const handleStartEdit = useCallback(() => {
    if (group) {
      setEditForm({
        name: group.name,
        description: group.description || '',
      })
      setIsEditing(true)
    }
  }, [group])

  // Save changes
  const handleSaveChanges = async () => {
    if (!editForm.name) {
      toast.error('Team name is required')
      return
    }

    try {
      await updateGroup({
        name: editForm.name,
        // "" clears the description (absent would mean unchanged).
        description: editForm.description.trim(),
      })
      toast.success('Team updated successfully')
      setIsEditing(false)
      mutateGroup()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to update team'))
    }
  }

  // Add member
  const handleAddMember = async () => {
    if (!newMember.userId) {
      toast.error('Please select a member')
      return
    }

    try {
      await addMember({
        user_id: newMember.userId,
        role: newMember.role,
      })
      toast.success('Member added successfully')
      setAddMemberDialogOpen(false)
      setNewMember({ userId: '', role: 'member' })
      mutateMembers()
      mutateGroup()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to add member'))
    }
  }

  // Remove member
  const handleRemoveMember = async () => {
    if (!memberToRemove) return

    try {
      await removeMember()
      toast.success(`Member removed successfully`)
      setMemberToRemove(null)
      mutateMembers()
      mutateGroup()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to remove member'))
    }
  }

  // Assign Asset
  const handleAssignAsset = async (
    assetId: string,
    ownershipType: 'primary' | 'secondary' | 'stakeholder' | 'informed'
  ) => {
    try {
      await assignAsset({
        asset_id: assetId,
        ownership_type: ownershipType,
      })
      toast.success('Asset assigned successfully')
      setAddAssetDialogOpen(false)
      mutateAssets()
      mutateGroup()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to assign asset'))
    }
  }

  // Unassign Asset
  const handleUnassignAsset = async () => {
    if (!assetToRemove) return

    try {
      await unassignAsset()
      toast.success('Asset removed successfully')
      setAssetToRemove(null)
      mutateAssets()
      mutateGroup()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to remove asset'))
    }
  }

  // Get available members (not already in group)
  const availableMembers = (tenantMembers || []).filter(
    (m: { user_id: string }) =>
      !members.some((gm: { user_id?: string; id?: string }) => {
        const gmId = gm.user_id || gm.id // defensive
        return gmId === m.user_id
      })
  )

  const groupType = group ? getGroupType(group) : null
  const typeLabel = groupType ? GroupTypeConfig[groupType]?.label : undefined
  const memberCount = group?.member_count ?? membersTotalCount ?? 0
  const assetCount = group?.asset_count ?? assetsTotalCount ?? 0

  const tabs: DetailTab<GroupTab>[] = [
    { value: 'overview', label: 'Overview' },
    {
      value: 'members',
      label: (
        <>
          Members
          <TabsCount value={memberCount} />
        </>
      ),
    },
    {
      value: 'assets',
      label: (
        <>
          Assets
          <TabsCount value={assetCount} />
        </>
      ),
    },
    { value: 'scope-rules', label: 'Scope rules' },
  ]

  const menu: DetailMenuItem[] = group
    ? [
        {
          label: 'Copy ID',
          icon: Hash,
          onSelect: () => {
            copyToClipboard(group.id)
            toast.success('Team ID copied to clipboard')
          },
        },
      ]
    : []

  return (
    <>
      <DetailSheet
        open={open}
        onOpenChange={onOpenChange}
        panel={group ? activeTab : undefined}
        header={
          <DetailHeader
            title={
              group && isEditing ? (
                <Input
                  autoFocus
                  aria-label="Team name"
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                  className="h-8 text-base font-semibold"
                  placeholder="Team name"
                />
              ) : (
                (group?.name ?? 'Team')
              )
            }
            badges={
              typeLabel ? (
                <Badge variant="outline" className="gap-1 text-xs font-normal">
                  {groupType === 'security_team' ? (
                    <ShieldCheck className="h-3 w-3" />
                  ) : (
                    <Users className="h-3 w-3" />
                  )}
                  {typeLabel}
                </Badge>
              ) : undefined
            }
            meta={group ? [`Created ${formatDate(group.created_at)}`] : undefined}
            actions={
              group ? (
                isEditing ? (
                  <>
                    <Button size="sm" onClick={handleSaveChanges} disabled={isUpdating}>
                      {isUpdating ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Save className="h-4 w-4" />
                      )}
                      Save
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setIsEditing(false)}>
                      Cancel
                    </Button>
                  </>
                ) : (
                  <Button size="sm" onClick={handleStartEdit}>
                    <Pencil className="h-4 w-4" />
                    Edit
                  </Button>
                )
              ) : undefined
            }
            menu={menu}
            onClose={() => onOpenChange(false)}
          />
        }
        tabs={
          group ? (
            <DetailTabs tabs={tabs} value={activeTab} onValueChange={setActiveTab} />
          ) : undefined
        }
      >
        {groupLoading ? (
          <div className="space-y-3" aria-hidden>
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : groupError ? (
          <ErrorDisplay
            error={groupErrorDetails}
            onClose={() => onOpenChange(false)}
            onRetry={() => mutateGroup()}
          />
        ) : !group ? (
          <ErrorDisplay
            error={{ status: 404 }}
            onClose={() => onOpenChange(false)}
            onRetry={() => mutateGroup()}
          />
        ) : (
          <>
            {activeTab === 'overview' && (
              <div className="space-y-5">
                <DetailStatGrid aria-label="Key numbers">
                  <DetailStat label="Members" value={memberCount} />
                  <DetailStat label="Assets" value={assetCount} />
                  <DetailStat label="Created" value={formatDate(group.created_at)} />
                </DetailStatGrid>

                <DetailSections>
                  <DetailSection title="Description">
                    {isEditing ? (
                      <Textarea
                        aria-label="Description"
                        value={editForm.description}
                        onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                        placeholder="Add a description..."
                        rows={3}
                      />
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        {group.description || 'No description provided.'}
                      </p>
                    )}
                  </DetailSection>

                  <DetailSection title="Details">
                    <DetailFieldGrid>
                      <DetailField label="Type">{typeLabel ?? '—'}</DetailField>
                      <DetailField label="Last updated">{formatDate(group.updated_at)}</DetailField>
                      <DetailField label="Team ID" full>
                        <DetailCopyId id={group.id} label="Team ID" />
                      </DetailField>
                    </DetailFieldGrid>
                  </DetailSection>
                </DetailSections>
              </div>
            )}

            {activeTab === 'members' && (
              <MembersTab
                members={members}
                totalCount={membersTotalCount}
                isLoading={membersLoading}
                limit={PAGE_SIZE}
                offset={membersOffset}
                onPageChange={setMembersOffset}
                onAddMember={() => setAddMemberDialogOpen(true)}
                onRemoveMember={(userId, name) => setMemberToRemove({ userId, name })}
              />
            )}

            {activeTab === 'assets' && (
              <AssetsTab
                assets={assets}
                totalCount={assetsTotalCount}
                isLoading={assetsLoading}
                limit={PAGE_SIZE}
                offset={assetsOffset}
                onPageChange={setAssetsOffset}
                onAddAsset={() => setAddAssetDialogOpen(true)}
                onBulkAddAssets={() => setBulkAddAssetsDialogOpen(true)}
                onRemoveAsset={(id, name) => setAssetToRemove({ id, name })}
              />
            )}

            {activeTab === 'scope-rules' && <ScopeRulesTab groupId={groupId} />}
          </>
        )}
      </DetailSheet>

      <AddMemberDialog
        open={addMemberDialogOpen}
        onOpenChange={setAddMemberDialogOpen}
        newMember={newMember}
        setNewMember={setNewMember}
        isAddingMember={isAddingMember}
        onAddMember={handleAddMember}
        availableMembers={availableMembers}
      />

      <AddAssetDialog
        open={addAssetDialogOpen}
        onOpenChange={setAddAssetDialogOpen}
        isAssigning={isAssigningAsset}
        onAssign={handleAssignAsset}
        existingAssets={assets}
      />

      <BulkAddAssetsDialog
        groupId={groupId}
        open={bulkAddAssetsDialogOpen}
        onOpenChange={setBulkAddAssetsDialogOpen}
        existingAssets={assets}
        onSuccess={() => {
          mutateAssets()
          mutateGroup()
          onUpdate?.()
        }}
      />

      {/* Remove Member Confirmation */}
      <Dialog open={!!memberToRemove} onOpenChange={(open) => !open && setMemberToRemove(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Remove Member</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove &quot;{memberToRemove?.name}&quot; from this team?
              They will lose access to assets owned by this team.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setMemberToRemove(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleRemoveMember} disabled={isRemovingMember}>
              {isRemovingMember ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="me-2 h-4 w-4" />
              )}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Remove Asset Confirmation */}
      <Dialog open={!!assetToRemove} onOpenChange={(open) => !open && setAssetToRemove(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Remove Asset</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove the asset &quot;{assetToRemove?.name}&quot; from this
              team? The team will lose access to this asset.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setAssetToRemove(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleUnassignAsset}
              disabled={isUnassigningAsset}
            >
              {isUnassigningAsset ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="me-2 h-4 w-4" />
              )}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
