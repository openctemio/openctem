'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import {
  AlertCircle,
  Hash,
  Loader2,
  Pencil,
  Play,
  Power,
  PowerOff,
  Save,
  Target,
  Trash2,
} from 'lucide-react'
import {
  useAssignmentRule,
  useUpdateAssignmentRule,
  useDeleteAssignmentRule,
  useGroups,
  formatDate,
  type TestRuleResult,
} from '@/features/access-control'
import { fetcherWithOptions } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  DetailCallout,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  type DetailMenuItem,
} from '@/features/shared'
import { useCanMutate } from '@/lib/permissions'
import { cn } from '@/lib/utils'

interface AssignmentRuleDetailSheetProps {
  ruleId: string | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onUpdate?: () => void
  onDelete?: () => void
}

export function AssignmentRuleDetailSheet({
  ruleId,
  open,
  onOpenChange,
  onUpdate,
  onDelete,
}: AssignmentRuleDetailSheetProps) {
  const { assignmentRule, isLoading, isError, mutate } = useAssignmentRule(open ? ruleId : null)
  const { updateAssignmentRule, isUpdating } = useUpdateAssignmentRule(open ? ruleId : null)
  const { deleteAssignmentRule, isDeleting } = useDeleteAssignmentRule(open ? ruleId : null)
  const { groups } = useGroups()
  const canWrite = useCanMutate('PUT /api/v1/assignment-rules/{id}')
  // Owner only on the API (RequireOwner).
  const canDelete = useCanMutate('DELETE /api/v1/assignment-rules/{id}')

  // Group lookup map: id → name
  const groupMap = useMemo(() => {
    const map: Record<string, string> = {}
    for (const g of groups) {
      map[g.id] = g.name
    }
    return map
  }, [groups])

  const [isEditing, setIsEditing] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [editForm, setEditForm] = useState({
    name: '',
    description: '',
    priority: 0,
    target_group_id: '',
    is_active: true,
  })

  // Populate edit form when rule loads
  useEffect(() => {
    if (assignmentRule && isEditing) {
      setEditForm({
        name: assignmentRule.name,
        description: assignmentRule.description || '',
        priority: assignmentRule.priority,
        target_group_id: assignmentRule.target_group_id,
        is_active: assignmentRule.is_active,
      })
    }
  }, [assignmentRule, isEditing])

  // Reset editing state when sheet closes
  useEffect(() => {
    if (!open) {
      setIsEditing(false)
    }
  }, [open])

  const handleStartEdit = () => {
    if (assignmentRule) {
      setEditForm({
        name: assignmentRule.name,
        description: assignmentRule.description || '',
        priority: assignmentRule.priority,
        target_group_id: assignmentRule.target_group_id,
        is_active: assignmentRule.is_active,
      })
      setIsEditing(true)
    }
  }

  const handleSave = async () => {
    if (!editForm.name) {
      toast.error('Rule name is required')
      return
    }

    try {
      await updateAssignmentRule({
        name: editForm.name,
        description: editForm.description.trim(),
        priority: editForm.priority,
        target_group_id: editForm.target_group_id,
        is_active: editForm.is_active,
      })
      toast.success('Assignment rule updated')
      setIsEditing(false)
      mutate()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to update rule'))
    }
  }

  const handleToggleActive = async () => {
    if (!assignmentRule) return

    try {
      await updateAssignmentRule({ is_active: !assignmentRule.is_active })
      toast.success(assignmentRule.is_active ? 'Rule deactivated' : 'Rule activated')
      mutate()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to update rule'))
    }
  }

  const handleDelete = async () => {
    try {
      await deleteAssignmentRule()
      toast.success('Assignment rule deleted')
      setDeleteDialogOpen(false)
      onOpenChange(false)
      onDelete?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to delete rule'))
    }
  }

  // Test rule via direct API call (avoids SWR mutation race condition)
  const handleTest = useCallback(async () => {
    if (!ruleId) return
    setIsTesting(true)
    try {
      const result = await fetcherWithOptions<TestRuleResult>(
        `/api/v1/assignment-rules/${ruleId}/test`,
        { method: 'POST' }
      )
      if (result) {
        toast.success(`Rule matched ${result.matching_findings} finding(s)`)
      }
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to test rule'))
    } finally {
      setIsTesting(false)
    }
  }, [ruleId])

  const conditionLabels: Record<string, string> = {
    asset_type: 'Asset Type',
    finding_severity: 'Finding Severity',
    finding_type: 'Finding Type',
    finding_source: 'Finding Source',
    asset_tags: 'Asset Tags',
    file_path_pattern: 'File Path Pattern',
  }

  const rule = assignmentRule
  const conditionEntries = Object.entries(rule?.conditions || {}).filter(
    ([, value]) => value && !(Array.isArray(value) && value.length === 0)
  )

  const menu: DetailMenuItem[] = []
  if (rule) {
    menu.push({
      label: 'Copy ID',
      icon: Hash,
      onSelect: () => {
        copyToClipboard(rule.id)
        toast.success('Rule ID copied to clipboard')
      },
    })
    if (canWrite) {
      menu.push({
        label: rule.is_active ? 'Deactivate' : 'Activate',
        icon: rule.is_active ? PowerOff : Power,
        onSelect: handleToggleActive,
      })
    }
    if (canDelete) {
      menu.push({
        label: 'Delete rule',
        icon: Trash2,
        destructive: true,
        separatorBefore: true,
        onSelect: () => setDeleteDialogOpen(true),
      })
    }
  }

  return (
    <>
      <DetailSheet
        open={open}
        onOpenChange={onOpenChange}
        width="lg"
        header={
          <DetailHeader
            title={
              rule && isEditing ? (
                <Input
                  autoFocus
                  aria-label="Rule name"
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                  className="h-8 text-base font-semibold"
                />
              ) : (
                (rule?.name ?? 'Assignment rule')
              )
            }
            badges={
              rule ? (
                <Badge
                  variant="outline"
                  className={cn(
                    'text-xs',
                    rule.is_active && 'border-success/30 bg-success/10 text-success'
                  )}
                >
                  {rule.is_active ? 'Active' : 'Inactive'}
                </Badge>
              ) : undefined
            }
            meta={
              rule
                ? [`Priority ${rule.priority}`, `Created ${formatDate(rule.created_at)}`]
                : undefined
            }
            actions={
              rule ? (
                isEditing ? (
                  <>
                    <Button size="sm" onClick={handleSave} disabled={isUpdating}>
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
                  <>
                    {canWrite && (
                      <Button size="sm" onClick={handleStartEdit}>
                        <Pencil className="h-4 w-4" />
                        Edit
                      </Button>
                    )}
                    <Button size="sm" variant="outline" onClick={handleTest} disabled={isTesting}>
                      {isTesting ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                      Test rule
                    </Button>
                  </>
                )
              ) : undefined
            }
            menu={menu}
            onClose={() => onOpenChange(false)}
          />
        }
      >
        {isLoading ? (
          <div className="space-y-3" aria-hidden>
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : isError || !rule ? (
          <DetailCallout
            tone="destructive"
            icon={AlertCircle}
            title="Failed to load assignment rule"
            actions={
              <Button variant="outline" size="sm" onClick={() => mutate()}>
                Try again
              </Button>
            }
          />
        ) : (
          <div className="space-y-5">
            {!rule.is_active && !isEditing && (
              <DetailCallout tone="warning" icon={AlertCircle} title="This rule is inactive">
                It does not route new findings until it is activated.
              </DetailCallout>
            )}

            <DetailSections>
              <DetailSection title="Description">
                {isEditing ? (
                  <Textarea
                    aria-label="Description"
                    value={editForm.description}
                    onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                    rows={2}
                  />
                ) : (
                  <p className="text-sm text-muted-foreground">
                    {rule.description || 'No description'}
                  </p>
                )}
              </DetailSection>

              <DetailSection title="Routing" icon={Target}>
                {isEditing ? (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="rule-priority">Priority</Label>
                      <Input
                        id="rule-priority"
                        type="number"
                        value={editForm.priority}
                        onChange={(e) =>
                          setEditForm({ ...editForm, priority: parseInt(e.target.value) || 0 })
                        }
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Target group</Label>
                      <Select
                        value={editForm.target_group_id}
                        onValueChange={(v) => setEditForm({ ...editForm, target_group_id: v })}
                      >
                        <SelectTrigger aria-label="Target group">
                          <SelectValue placeholder="Select group" />
                        </SelectTrigger>
                        <SelectContent>
                          {groups.map((g) => (
                            <SelectItem key={g.id} value={g.id}>
                              {g.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex items-center justify-between">
                      <Label>Active</Label>
                      <Switch
                        aria-label="Active"
                        checked={editForm.is_active}
                        onCheckedChange={(v) => setEditForm({ ...editForm, is_active: v })}
                      />
                    </div>
                  </div>
                ) : (
                  <DetailFieldGrid>
                    <DetailField label="Target group">
                      {groupMap[rule.target_group_id] || 'Unknown group'}
                    </DetailField>
                    <DetailField label="Priority">{rule.priority}</DetailField>
                  </DetailFieldGrid>
                )}
              </DetailSection>

              <DetailSection title="Conditions" count={conditionEntries.length}>
                {conditionEntries.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No conditions defined</p>
                ) : (
                  <DetailFieldGrid>
                    {conditionEntries.map(([key, value]) => (
                      <DetailField key={key} label={conditionLabels[key] || key} full>
                        <span className="flex flex-wrap gap-1">
                          {(Array.isArray(value) ? value : [value]).map((v) => (
                            <Badge key={String(v)} variant="outline" className="text-xs">
                              {String(v)}
                            </Badge>
                          ))}
                        </span>
                      </DetailField>
                    ))}
                  </DetailFieldGrid>
                )}
              </DetailSection>

              <DetailSection title="Details">
                <DetailFieldGrid>
                  <DetailField label="Created">{formatDate(rule.created_at)}</DetailField>
                  <DetailField label="Updated">{formatDate(rule.updated_at)}</DetailField>
                  <DetailField label="Rule ID" full>
                    <DetailCopyId id={rule.id} label="Rule ID" />
                  </DetailField>
                </DetailFieldGrid>
              </DetailSection>
            </DetailSections>
          </div>
        )}
      </DetailSheet>

      {/* Delete Confirmation */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Trash2 className="h-5 w-5" />
              Delete Assignment Rule
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{assignmentRule?.name}&quot;? This action cannot
              be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDeleteDialogOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDelete} disabled={isDeleting}>
              {isDeleting ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="me-2 h-4 w-4" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
