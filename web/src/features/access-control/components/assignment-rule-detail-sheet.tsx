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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

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
  const { t } = useTranslation()
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
      toast.error(t('org.ruleDetail.nameRequired', 'Rule name is required'))
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
      toast.success(t('org.ruleDetail.updated', 'Assignment rule updated'))
      setIsEditing(false)
      mutate()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, t('org.ruleDetail.updateFailed', 'Failed to update rule')))
    }
  }

  const handleToggleActive = async () => {
    if (!assignmentRule) return

    try {
      await updateAssignmentRule({ is_active: !assignmentRule.is_active })
      toast.success(
        assignmentRule.is_active
          ? t('org.ruleDetail.deactivated', 'Rule deactivated')
          : t('org.ruleDetail.activated', 'Rule activated')
      )
      mutate()
      onUpdate?.()
    } catch (error) {
      toast.error(getErrorMessage(error, t('org.ruleDetail.updateFailed', 'Failed to update rule')))
    }
  }

  const handleDelete = async () => {
    try {
      await deleteAssignmentRule()
      toast.success(t('org.ruleDetail.deleted', 'Assignment rule deleted'))
      setDeleteDialogOpen(false)
      onOpenChange(false)
      onDelete?.()
    } catch (error) {
      toast.error(getErrorMessage(error, t('org.ruleDetail.deleteFailed', 'Failed to delete rule')))
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
        toast.success(
          t('org.assignmentRules.testMatched', 'Rule matched {count} finding(s)', {
            count: result.matching_findings,
          })
        )
      }
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('org.assignmentRules.testFailed', 'Failed to test rule'))
      )
    } finally {
      setIsTesting(false)
    }
  }, [ruleId, t])

  const conditionLabels: Record<string, string> = {
    asset_type: t('org.assignmentRules.cond.asset_type', 'Asset type'),
    finding_severity: t('org.assignmentRules.cond.finding_severity', 'Severity'),
    finding_type: t('org.assignmentRules.cond.finding_type', 'Finding type'),
    finding_source: t('org.assignmentRules.cond.finding_source', 'Source'),
    asset_tags: t('org.assignmentRules.cond.asset_tags', 'Tags'),
    file_path_pattern: t('org.assignmentRules.cond.file_path_pattern', 'File path'),
  }

  const rule = assignmentRule
  const conditionEntries = Object.entries(rule?.conditions || {}).filter(
    ([, value]) => value && !(Array.isArray(value) && value.length === 0)
  )

  const menu: DetailMenuItem[] = []
  if (rule) {
    menu.push({
      label: t('org.ruleDetail.copyId', 'Copy ID'),
      icon: Hash,
      onSelect: () => {
        copyToClipboard(rule.id)
        toast.success(t('org.ruleDetail.idCopied', 'Rule ID copied'))
      },
    })
    if (canWrite) {
      menu.push({
        label: rule.is_active
          ? t('org.ruleDetail.deactivate', 'Deactivate')
          : t('org.ruleDetail.activate', 'Activate'),
        icon: rule.is_active ? PowerOff : Power,
        onSelect: handleToggleActive,
      })
    }
    if (canDelete) {
      menu.push({
        label: t('org.ruleDetail.deleteRule', 'Delete rule'),
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
                  aria-label={t('org.ruleDetail.ruleName', 'Rule name')}
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                  className="h-8 text-base font-semibold"
                />
              ) : (
                (rule?.name ?? t('org.ruleDetail.fallbackTitle', 'Assignment rule'))
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
                  {rule.is_active
                    ? t('org.assignmentRules.status.active', 'Active')
                    : t('org.assignmentRules.status.inactive', 'Inactive')}
                </Badge>
              ) : undefined
            }
            meta={
              rule
                ? [
                    t('org.ruleDetail.metaPriority', 'Priority {priority}', {
                      priority: rule.priority,
                    }),
                    t('org.ruleDetail.metaCreated', 'Created {date}', {
                      date: formatDate(rule.created_at),
                    }),
                  ]
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
                      {t('org.ruleDetail.save', 'Save')}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setIsEditing(false)}>
                      {t('common.cancel', 'Cancel')}
                    </Button>
                  </>
                ) : (
                  <>
                    {canWrite && (
                      <Button size="sm" onClick={handleStartEdit}>
                        <Pencil className="h-4 w-4" />
                        {t('org.assignmentRules.edit', 'Edit')}
                      </Button>
                    )}
                    <Button size="sm" variant="outline" onClick={handleTest} disabled={isTesting}>
                      {isTesting ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                      {t('org.assignmentRules.testRule', 'Test rule')}
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
            title={t('org.ruleDetail.loadFailed', 'Failed to load assignment rule')}
            actions={
              <Button variant="outline" size="sm" onClick={() => mutate()}>
                {t('org.ruleDetail.tryAgain', 'Try again')}
              </Button>
            }
          />
        ) : (
          <div className="space-y-5">
            {!rule.is_active && !isEditing && (
              <DetailCallout
                tone="warning"
                icon={AlertCircle}
                title={t('org.ruleDetail.inactiveTitle', 'This rule is inactive')}
              >
                {t(
                  'org.ruleDetail.inactiveBody',
                  'It does not route new findings until it is activated.'
                )}
              </DetailCallout>
            )}

            <DetailSections>
              <DetailSection title={t('org.ruleDetail.description', 'Description')}>
                {isEditing ? (
                  <Textarea
                    aria-label={t('org.ruleDetail.description', 'Description')}
                    value={editForm.description}
                    onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                    rows={2}
                  />
                ) : (
                  <p className="text-sm text-muted-foreground">
                    {rule.description || t('org.ruleDetail.noDescription', 'No description')}
                  </p>
                )}
              </DetailSection>

              <DetailSection title={t('org.ruleDetail.routing', 'Routing')} icon={Target}>
                {isEditing ? (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="rule-priority">
                        {t('org.assignmentRules.col.priority', 'Priority')}
                      </Label>
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
                      <Label htmlFor="rule-detail-team">
                        {t('org.assignmentRules.targetTeam', 'Target team')}
                      </Label>
                      <Select
                        value={editForm.target_group_id}
                        onValueChange={(v) => setEditForm({ ...editForm, target_group_id: v })}
                      >
                        <SelectTrigger id="rule-detail-team">
                          <SelectValue
                            placeholder={t('org.ruleDetail.selectTeam', 'Select team')}
                          />
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
                      <Label htmlFor="rule-detail-active">
                        {t('org.ruleDetail.active', 'Active')}
                      </Label>
                      <Switch
                        id="rule-detail-active"
                        checked={editForm.is_active}
                        onCheckedChange={(v) => setEditForm({ ...editForm, is_active: v })}
                      />
                    </div>
                  </div>
                ) : (
                  <DetailFieldGrid>
                    <DetailField label={t('org.assignmentRules.targetTeam', 'Target team')}>
                      {groupMap[rule.target_group_id] ||
                        t('org.ruleDetail.unknownTeam', 'Unknown team')}
                    </DetailField>
                    <DetailField label={t('org.assignmentRules.col.priority', 'Priority')}>
                      {rule.priority}
                    </DetailField>
                  </DetailFieldGrid>
                )}
              </DetailSection>

              <DetailSection
                title={t('org.ruleDetail.conditions', 'Conditions')}
                count={conditionEntries.length}
              >
                {conditionEntries.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    {t('org.ruleDetail.noConditions', 'No conditions defined')}
                  </p>
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

              <DetailSection title={t('org.ruleDetail.details', 'Details')}>
                <DetailFieldGrid>
                  <DetailField label={t('org.ruleDetail.created', 'Created')}>
                    {formatDate(rule.created_at)}
                  </DetailField>
                  <DetailField label={t('org.ruleDetail.updatedAt', 'Updated')}>
                    {formatDate(rule.updated_at)}
                  </DetailField>
                  <DetailField label={t('org.ruleDetail.ruleId', 'Rule ID')} full>
                    <DetailCopyId id={rule.id} label={t('org.ruleDetail.ruleId', 'Rule ID')} />
                  </DetailField>
                </DetailFieldGrid>
              </DetailSection>
            </DetailSections>
          </div>
        )}
      </DetailSheet>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        destructive
        title={t('confirm.assignmentRule.deleteTitle', 'Delete the assignment rule "{name}"?', {
          name: assignmentRule?.name ?? '',
        })}
        desc={t(
          'confirm.assignmentRule.deleteDesc',
          'New findings are no longer routed by it. Findings it already assigned keep their owner. This cannot be undone.'
        )}
        confirmText={
          isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
        }
        isLoading={isDeleting}
        handleConfirm={handleDelete}
      />
    </>
  )
}
