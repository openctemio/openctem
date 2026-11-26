'use client'

import { useState, useEffect } from 'react'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { TagInput } from '@/components/ui/tag-input'
import { Loader2, Plus, Save } from 'lucide-react'
import { useAssetTags } from '@/features/assets/hooks/use-asset-tags'
import { useAssetGroups } from '@/features/asset-groups/hooks/use-asset-groups'
import type {
  ScopeRule,
  ScopeRuleType,
  MatchLogic,
  OwnershipType,
  CreateScopeRuleInput,
  UpdateScopeRuleInput,
} from '@/features/access-control/types'
import { useTranslation } from '@/context/i18n-provider'

interface ScopeRuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  rule?: ScopeRule | null
  isSubmitting: boolean
  onSubmit: (data: CreateScopeRuleInput | UpdateScopeRuleInput) => Promise<void>
}

export function ScopeRuleDialog({
  open,
  onOpenChange,
  rule,
  isSubmitting,
  onSubmit,
}: ScopeRuleDialogProps) {
  const { t } = useTranslation()
  const isEditing = !!rule

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [ruleType, setRuleType] = useState<ScopeRuleType>('tag_match')
  const [matchTags, setMatchTags] = useState<string[]>([])
  const [matchLogic, setMatchLogic] = useState<MatchLogic>('any')
  const [matchAssetGroupIds, setMatchAssetGroupIds] = useState<string[]>([])
  const [ownershipType, setOwnershipType] = useState<OwnershipType>('secondary')
  const [priority, setPriority] = useState(0)

  // Tag autocomplete
  const { tags: tagSuggestions } = useAssetTags(undefined, open)

  // Asset groups for selection
  const { data: assetGroups } = useAssetGroups({
    enabled: open && ruleType === 'asset_group_match',
  })

  // Populate form when editing
  useEffect(() => {
    if (open && rule) {
      setName(rule.name)
      setDescription(rule.description || '')
      setRuleType(rule.rule_type)
      setMatchTags(rule.match_tags || [])
      setMatchLogic(rule.match_logic || 'any')
      setMatchAssetGroupIds(rule.match_asset_group_ids || [])
      setOwnershipType(rule.ownership_type || 'secondary')
      setPriority(rule.priority || 0)
    } else if (open && !rule) {
      setName('')
      setDescription('')
      setRuleType('tag_match')
      setMatchTags([])
      setMatchLogic('any')
      setMatchAssetGroupIds([])
      setOwnershipType('secondary')
      setPriority(0)
    }
  }, [open, rule])

  const handleSubmit = async () => {
    if (!name.trim()) return

    if (isEditing) {
      const data: UpdateScopeRuleInput = {
        name: name.trim(),
        description: description.trim(),
        match_tags: ruleType === 'tag_match' ? matchTags : undefined,
        match_logic: ruleType === 'tag_match' ? matchLogic : undefined,
        match_asset_group_ids: ruleType === 'asset_group_match' ? matchAssetGroupIds : undefined,
        ownership_type: ownershipType,
        priority,
      }
      await onSubmit(data)
    } else {
      const data: CreateScopeRuleInput = {
        name: name.trim(),
        description: description.trim(),
        rule_type: ruleType,
        match_tags: ruleType === 'tag_match' ? matchTags : undefined,
        match_logic: ruleType === 'tag_match' ? matchLogic : undefined,
        match_asset_group_ids: ruleType === 'asset_group_match' ? matchAssetGroupIds : undefined,
        ownership_type: ownershipType,
        priority,
      }
      await onSubmit(data)
    }
  }

  const isValid =
    name.trim() && (ruleType === 'tag_match' ? matchTags.length > 0 : matchAssetGroupIds.length > 0)

  const toggleAssetGroup = (groupId: string) => {
    setMatchAssetGroupIds((prev) =>
      prev.includes(groupId) ? prev.filter((id) => id !== groupId) : [...prev, groupId]
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {isEditing
              ? t('org.scopeRuleDialog.editTitle', 'Edit scope rule')
              : t('org.scopeRuleDialog.createTitle', 'Create scope rule')}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? t('org.scopeRuleDialog.editDescription', 'Update the scope rule configuration.')
              : t(
                  'org.scopeRuleDialog.createDescription',
                  'Define a rule to automatically assign assets to this team.'
                )}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="space-y-4 py-4">
            {/* Name */}
            <div className="space-y-2">
              <Label htmlFor="rule-name">{t('org.scopeRuleDialog.name', 'Name')}</Label>
              <Input
                id="rule-name"
                placeholder={t('org.scopeRuleDialog.namePlaceholder', 'e.g., Production Assets')}
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={200}
              />
            </div>

            {/* Description */}
            <div className="space-y-2">
              <Label htmlFor="rule-description">
                {t('org.scopeRuleDialog.description', 'Description')}
              </Label>
              <Textarea
                id="rule-description"
                placeholder={t(
                  'org.scopeRuleDialog.descriptionPlaceholder',
                  'Optional description...'
                )}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
              />
            </div>

            {/* Rule Type (only when creating) */}
            {!isEditing && (
              <div className="space-y-2">
                <Label>{t('org.scopeRuleDialog.ruleType', 'Rule type')}</Label>
                <Select value={ruleType} onValueChange={(v: ScopeRuleType) => setRuleType(v)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="tag_match">
                      <div className="flex flex-col">
                        <span className="font-medium">
                          {t('org.scopeRuleDialog.tagMatch', 'Tag match')}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {t('org.scopeRuleDialog.tagMatchHint', 'Match assets by their tags')}
                        </span>
                      </div>
                    </SelectItem>
                    <SelectItem value="asset_group_match">
                      <div className="flex flex-col">
                        <span className="font-medium">
                          {t('org.scopeRuleDialog.groupMatch', 'Asset group match')}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {t(
                            'org.scopeRuleDialog.groupMatchHint',
                            'Match assets by asset group membership'
                          )}
                        </span>
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}

            {/* Tag Match Configuration */}
            {ruleType === 'tag_match' && (
              <>
                <div className="space-y-2">
                  <Label>{t('org.scopeRuleDialog.matchTags', 'Match tags (max 10)')}</Label>
                  <TagInput
                    value={matchTags}
                    onChange={setMatchTags}
                    suggestions={tagSuggestions}
                    placeholder={t(
                      'org.scopeRuleDialog.tagPlaceholder',
                      'Type a tag and press Enter...'
                    )}
                    maxTags={10}
                  />
                </div>

                <div className="space-y-2">
                  <Label>{t('org.scopeRuleDialog.matchLogic', 'Match logic')}</Label>
                  <Select value={matchLogic} onValueChange={(v: MatchLogic) => setMatchLogic(v)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="any">
                        <div className="flex flex-col">
                          <span className="font-medium">
                            {t('org.scopeRuleDialog.any', 'Any (OR)')}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {t(
                              'org.scopeRuleDialog.anyHint',
                              'Asset matches if it has ANY of the tags'
                            )}
                          </span>
                        </div>
                      </SelectItem>
                      <SelectItem value="all">
                        <div className="flex flex-col">
                          <span className="font-medium">
                            {t('org.scopeRuleDialog.all', 'All (AND)')}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {t('org.scopeRuleDialog.allHint', 'Asset must have ALL of the tags')}
                          </span>
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </>
            )}

            {/* Asset Group Match Configuration */}
            {ruleType === 'asset_group_match' && (
              <div className="space-y-2">
                <Label>
                  {t('org.scopeRuleDialog.selectGroups', 'Select asset groups (max 5)')}
                </Label>
                <div className="border rounded-md max-h-[200px] overflow-y-auto p-1 space-y-1">
                  {assetGroups.length === 0 ? (
                    <div className="p-4 text-center text-muted-foreground text-sm">
                      {t('org.scopeRuleDialog.noGroups', 'No asset groups found')}
                    </div>
                  ) : (
                    assetGroups.map((group) => {
                      const selected = matchAssetGroupIds.includes(group.id)
                      const disabled = !selected && matchAssetGroupIds.length >= 5

                      return (
                        <div
                          key={group.id}
                          className={`
                          flex items-center justify-between p-2 rounded-sm cursor-pointer text-sm
                          ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:bg-muted'}
                          ${selected ? 'bg-primary/10 border-primary/20 border' : ''}
                        `}
                          onClick={() => !disabled && toggleAssetGroup(group.id)}
                        >
                          <div className="flex flex-col truncate">
                            <span className="font-medium truncate">{group.name}</span>
                            {group.description && (
                              <span className="text-xs text-muted-foreground truncate">
                                {group.description}
                              </span>
                            )}
                          </div>
                        </div>
                      )
                    })
                  )}
                </div>
                {matchAssetGroupIds.length > 0 && (
                  <p className="text-xs text-muted-foreground text-end">
                    {t(
                      'org.scopeRuleDialog.groupsSelected',
                      '{count, plural, one {# group selected} other {# groups selected}}',
                      { count: matchAssetGroupIds.length }
                    )}
                  </p>
                )}
              </div>
            )}

            {/* Ownership Type */}
            <div className="space-y-2">
              <Label>{t('org.ownership.type', 'Ownership type')}</Label>
              <Select
                value={ownershipType}
                onValueChange={(v: OwnershipType) => setOwnershipType(v)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="primary">
                    {t('assets.ownershipType.primary', 'Primary')}
                  </SelectItem>
                  <SelectItem value="secondary">
                    {t('assets.ownershipType.secondary', 'Secondary')}
                  </SelectItem>
                  <SelectItem value="stakeholder">
                    {t('assets.ownershipType.stakeholder', 'Stakeholder')}
                  </SelectItem>
                  <SelectItem value="informed">
                    {t('assets.ownershipType.informed', 'Informed')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Priority */}
            <div className="space-y-2">
              <Label htmlFor="rule-priority">{t('org.scopeRuleDialog.priority', 'Priority')}</Label>
              <Input
                id="rule-priority"
                type="number"
                min={0}
                max={100}
                value={priority}
                onChange={(e) => setPriority(Number(e.target.value))}
              />
              <p className="text-xs text-muted-foreground">
                {t(
                  'org.scopeRuleDialog.priorityHint',
                  'Higher priority rules are evaluated first (0-100)'
                )}
              </p>
            </div>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={isSubmitting || !isValid}>
            {isSubmitting ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : isEditing ? (
              <Save className="me-2 h-4 w-4" />
            ) : (
              <Plus className="me-2 h-4 w-4" />
            )}
            {isEditing
              ? t('org.scopeRuleDialog.saveChanges', 'Save changes')
              : t('org.scopeRuleDialog.createRule', 'Create rule')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
