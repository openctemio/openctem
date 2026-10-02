'use client'

import { useState, useCallback, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
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
import {
  Check,
  Hash,
  KeyRound,
  Loader2,
  Lock,
  Pencil,
  Plus,
  Save,
  Shield,
  Trash2,
} from 'lucide-react'
import {
  usePermissionSet,
  useUpdatePermissionSet,
  useAddPermissionToSet,
  useRemovePermissionFromSet,
  PermissionCategories,
  getPermissionInfo,
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
  EmptyState,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'

type PermissionSetTab = 'overview' | 'permissions'

interface PermissionSetDetailSheetProps {
  permissionSetId: string | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onUpdate?: () => void
}

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

export function PermissionSetDetailSheet({
  permissionSetId,
  open,
  onOpenChange,
  onUpdate,
}: PermissionSetDetailSheetProps) {
  // API Hooks
  const {
    permissionSet,
    isLoading,
    mutate: mutatePermissionSet,
  } = usePermissionSet(permissionSetId)
  const { updatePermissionSet, isUpdating } = useUpdatePermissionSet(permissionSetId)
  const { addPermission, isAdding } = useAddPermissionToSet(permissionSetId)

  // UI State
  const [activeTab, setActiveTab] = useState<PermissionSetTab>('overview')
  const [isEditing, setIsEditing] = useState(false)
  const [editForm, setEditForm] = useState({ name: '', description: '' })
  const [addPermissionDialogOpen, setAddPermissionDialogOpen] = useState(false)
  const [permissionToRemove, setPermissionToRemove] = useState<{ id: string; key: string } | null>(
    null
  )
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([])

  // Remove permission hook
  const { removePermission, isRemoving } = useRemovePermissionFromSet(
    permissionSetId,
    permissionToRemove?.id || null
  )

  // A different set starts on its overview, not in edit mode.
  useEffect(() => {
    setActiveTab('overview')
    setIsEditing(false)
  }, [permissionSetId])

  // Start editing
  const handleStartEdit = useCallback(() => {
    if (permissionSet) {
      setEditForm({
        name: permissionSet.name,
        description: permissionSet.description || '',
      })
      setIsEditing(true)
    }
  }, [permissionSet])

  // Save changes
  const handleSaveChanges = async () => {
    if (!editForm.name) {
      toast.error('Name is required')
      return
    }

    try {
      await updatePermissionSet({
        name: editForm.name,
        description: editForm.description || undefined,
      })
      toast.success('Permission set updated successfully')
      setIsEditing(false)
      mutatePermissionSet()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to update permission set'))
    }
  }

  // Toggle permission selection
  const togglePermissionSelection = (permission: string) => {
    setSelectedPermissions((prev) =>
      prev.includes(permission) ? prev.filter((p) => p !== permission) : [...prev, permission]
    )
  }

  // Add permissions
  const handleAddPermissions = async () => {
    if (selectedPermissions.length === 0) {
      toast.error('Please select at least one permission')
      return
    }

    const results = {
      success: [] as string[],
      failed: [] as { permission: string; error: string }[],
    }

    try {
      // Add permissions one by one with individual error handling
      for (const permission of selectedPermissions) {
        try {
          await addPermission({ permission })
          results.success.push(permission)
        } catch (error) {
          results.failed.push({
            permission,
            error: error instanceof Error ? error.message : 'Unknown error',
          })
        }
      }

      // Show detailed results
      if (results.success.length > 0 && results.failed.length === 0) {
        toast.success(`Added ${results.success.length} permission(s) successfully`)
      } else if (results.success.length > 0 && results.failed.length > 0) {
        toast.warning(
          `Added ${results.success.length} permission(s). Failed to add ${results.failed.length} permission(s).`,
          {
            description: results.failed.map((f) => `• ${f.permission}: ${f.error}`).join('\n'),
          }
        )
      } else {
        toast.error(`Failed to add all ${results.failed.length} permission(s)`, {
          description: results.failed.map((f) => `• ${f.permission}: ${f.error}`).join('\n'),
        })
      }

      // Close dialog and refresh if any succeeded
      if (results.success.length > 0) {
        setAddPermissionDialogOpen(false)
        setSelectedPermissions([])
        mutatePermissionSet()
        onUpdate?.()
      }
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to add permissions'))
    }
  }

  // Remove permission
  const handleRemovePermission = async () => {
    if (!permissionToRemove) return

    try {
      await removePermission()
      toast.success('Permission removed successfully')
      setPermissionToRemove(null)
      mutatePermissionSet()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to remove permission'))
    }
  }

  // Get current permission keys
  const currentPermissionKeys =
    permissionSet?.items?.map((p: { permission: string }) => p.permission) || []

  // Get available permissions (not already in set)
  const availablePermissions = PermissionCategories.map((category) => ({
    ...category,
    permissions: category.permissions.filter((p) => !currentPermissionKeys.includes(p.key)),
  })).filter((c) => c.permissions.length > 0)

  const isSystem = permissionSet?.is_system

  const permissionCount = permissionSet?.permissions?.length || 0

  const tabs: DetailTab<PermissionSetTab>[] = [
    { value: 'overview', label: 'Overview' },
    {
      value: 'permissions',
      label: (
        <>
          Permissions
          <TabsCount value={permissionCount} />
        </>
      ),
    },
  ]

  const menu: DetailMenuItem[] = permissionSet
    ? [
        {
          label: 'Copy ID',
          icon: Hash,
          onSelect: () => {
            copyToClipboard(permissionSet.id)
            toast.success('Permission set ID copied to clipboard')
          },
        },
      ]
    : []

  return (
    <>
      <DetailSheet
        open={open}
        onOpenChange={onOpenChange}
        panel={permissionSet ? activeTab : undefined}
        header={
          <DetailHeader
            title={
              permissionSet && isEditing ? (
                <Input
                  autoFocus
                  aria-label="Permission set name"
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                  className="h-8 text-base font-semibold"
                />
              ) : (
                (permissionSet?.name ?? 'Permission set')
              )
            }
            badges={
              permissionSet ? (
                <>
                  <Badge variant="outline" className="gap-1 text-xs font-normal">
                    {isSystem ? <Lock className="h-3 w-3" /> : <KeyRound className="h-3 w-3" />}
                    {isSystem ? 'System' : 'Custom'}
                  </Badge>
                  {isSystem && (
                    <Badge variant="outline" className="text-xs font-normal">
                      Read-only
                    </Badge>
                  )}
                </>
              ) : undefined
            }
            meta={permissionSet ? [`Created ${formatDate(permissionSet.created_at)}`] : undefined}
            actions={
              permissionSet && !isSystem ? (
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
          permissionSet ? (
            <DetailTabs tabs={tabs} value={activeTab} onValueChange={setActiveTab} />
          ) : undefined
        }
      >
        {isLoading ? (
          <div className="space-y-3" aria-hidden>
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : !permissionSet ? (
          <EmptyState icon={Shield} title="Permission set not found" card={false} />
        ) : (
          <>
            {activeTab === 'overview' && (
              <div className="space-y-5">
                <DetailStatGrid aria-label="Key numbers">
                  <DetailStat label="Permissions" value={permissionCount} />
                  <DetailStat label="Teams using it" value={permissionSet.group_count || 0} />
                  <DetailStat label="Created" value={formatDate(permissionSet.created_at)} />
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
                        {permissionSet.description || 'No description provided.'}
                      </p>
                    )}
                  </DetailSection>

                  <DetailSection title="Details">
                    <DetailFieldGrid>
                      <DetailField label="Type">{isSystem ? 'System' : 'Custom'}</DetailField>
                      <DetailField label="Last updated">
                        {formatDate(permissionSet.updated_at)}
                      </DetailField>
                      <DetailField label="Permission set ID" full>
                        <DetailCopyId id={permissionSet.id} label="Permission set ID" />
                      </DetailField>
                    </DetailFieldGrid>
                  </DetailSection>
                </DetailSections>
              </div>
            )}

            {activeTab === 'permissions' && (
              <DetailSection
                title="Permissions"
                count={permissionCount}
                actions={
                  !isSystem ? (
                    <Button size="sm" onClick={() => setAddPermissionDialogOpen(true)}>
                      <Plus className="h-4 w-4" />
                      Add permission
                    </Button>
                  ) : undefined
                }
              >
                {permissionCount === 0 ? (
                  <EmptyState icon={Shield} title="No permissions in this set" card={false} />
                ) : (
                  <ul className="divide-y rounded-lg border">
                    {permissionSet.permissions!.map((permission: string, index: number) => {
                      const info = getPermissionInfo(permission)
                      const label = info?.label || permission
                      return (
                        <li
                          key={`${permission}-${index}`}
                          className="flex items-center gap-3 px-3 py-2.5"
                        >
                          <Check className="h-4 w-4 shrink-0 text-success" />
                          <div className="min-w-0 flex-1">
                            <p className="text-sm font-medium break-words">{label}</p>
                            {info?.description && (
                              <p className="text-xs text-muted-foreground">{info.description}</p>
                            )}
                          </div>
                          {!isSystem && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8 shrink-0 text-muted-foreground hover:text-destructive"
                              aria-label={`Remove ${label}`}
                              onClick={() =>
                                setPermissionToRemove({ id: permission, key: permission })
                              }
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
                        </li>
                      )
                    })}
                  </ul>
                )}
              </DetailSection>
            )}
          </>
        )}
      </DetailSheet>

      {/* Add Permission Dialog */}
      <Dialog open={addPermissionDialogOpen} onOpenChange={setAddPermissionDialogOpen}>
        <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Permissions</DialogTitle>
            <DialogDescription>Select permissions to add to this permission set.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <p className="text-sm text-muted-foreground">
              Selected: {selectedPermissions.length} permissions
            </p>

            {availablePermissions.length === 0 ? (
              <EmptyState
                icon={Shield}
                title="All permissions are already in this set"
                card={false}
              />
            ) : (
              <div className="space-y-4 max-h-[400px] overflow-y-auto pe-2">
                {availablePermissions.map((category) => (
                  <div key={category.name} className="space-y-2">
                    <h4 className="text-sm font-medium text-muted-foreground">{category.name}</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {category.permissions.map((permission) => {
                        const isSelected = selectedPermissions.includes(permission.key)
                        return (
                          <div
                            key={permission.key}
                            onClick={() => togglePermissionSelection(permission.key)}
                            className={`
                              flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all
                              ${
                                isSelected
                                  ? 'border-primary bg-primary/5'
                                  : 'border-border hover:border-muted-foreground/30'
                              }
                            `}
                          >
                            <Checkbox
                              checked={isSelected}
                              onCheckedChange={() => togglePermissionSelection(permission.key)}
                              className="mt-0.5"
                            />
                            <div className="flex-1 min-w-0">
                              <p className="font-medium text-sm">{permission.label}</p>
                              <p className="text-xs text-muted-foreground line-clamp-2">
                                {permission.description}
                              </p>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setAddPermissionDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleAddPermissions}
              disabled={isAdding || selectedPermissions.length === 0}
            >
              {isAdding ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
              ) : (
                <Plus className="me-2 h-4 w-4" />
              )}
              Add {selectedPermissions.length} Permission
              {selectedPermissions.length !== 1 ? 's' : ''}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Remove Permission Confirmation */}
      <Dialog
        open={!!permissionToRemove}
        onOpenChange={(open) => !open && setPermissionToRemove(null)}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Remove Permission</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove the &quot;
              {getPermissionInfo(permissionToRemove?.key || '')?.label || permissionToRemove?.key}
              &quot; permission? Groups using this permission set will lose this permission.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPermissionToRemove(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleRemovePermission} disabled={isRemoving}>
              {isRemoving ? (
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
