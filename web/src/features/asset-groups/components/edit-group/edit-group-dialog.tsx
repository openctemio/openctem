/**
 * Edit Group Dialog
 *
 * Modern dialog for editing asset group metadata with visual selectors
 * matching the Create wizard for UI consistency.
 *
 * Asset management is handled separately in the Assets tab for better UX.
 */

'use client'

import { useState, useCallback, useEffect } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Building2,
  User,
  Mail,
  Tags,
  X,
  ChevronDown,
  AlertTriangle,
  AlertCircle,
  Info,
  MinusCircle,
  Server,
  TestTube,
  Code,
  FlaskConical,
  Loader2,
  Pencil,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { BusinessUnitField } from '../business-unit-field'
import { GroupMembersSection } from '../members/group-members-section'
import { useTranslation } from '@/context/i18n-provider'
import type { Environment, Criticality } from '@/features/shared/types'
import type { AssetGroup } from '../../types'

interface EditGroupDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  group: AssetGroup
  onSubmit: (data: EditGroupFormData) => Promise<void>
  isSubmitting?: boolean
}

export interface EditGroupFormData {
  name: string
  description: string
  environment: Environment
  criticality: Criticality
  businessUnit: string
  owner: string
  ownerEmail: string
  tags: string[]
}

const ENVIRONMENTS: {
  value: Environment
  labelKey: string
  icon: typeof Server
  color: string
}[] = [
  {
    value: 'production',
    labelKey: 'assetGroups.environment.production',
    icon: Server,
    color: 'text-foreground border-border bg-muted',
  },
  {
    value: 'staging',
    labelKey: 'assetGroups.environment.staging',
    icon: FlaskConical,
    color: 'text-foreground border-border bg-muted',
  },
  {
    value: 'development',
    labelKey: 'assetGroups.environment.development',
    icon: Code,
    color: 'text-foreground border-border bg-muted',
  },
  {
    value: 'testing',
    labelKey: 'assetGroups.environment.testing',
    icon: TestTube,
    color: 'text-foreground border-border bg-muted',
  },
]

const CRITICALITIES: {
  value: Criticality
  labelKey: string
  descriptionKey: string
  icon: typeof AlertTriangle
  color: string
  bgColor: string
}[] = [
  {
    value: 'critical',
    labelKey: 'assetGroups.basic.crit.critical',
    descriptionKey: 'assetGroups.edit.crit.criticalDesc',
    icon: AlertTriangle,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
  {
    value: 'high',
    labelKey: 'assetGroups.basic.crit.high',
    descriptionKey: 'assetGroups.edit.crit.highDesc',
    icon: AlertCircle,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
  {
    value: 'medium',
    labelKey: 'assetGroups.basic.crit.medium',
    descriptionKey: 'assetGroups.edit.crit.mediumDesc',
    icon: Info,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
  {
    value: 'low',
    labelKey: 'assetGroups.basic.crit.low',
    descriptionKey: 'assetGroups.edit.crit.lowDesc',
    icon: MinusCircle,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
]

const SUGGESTED_TAGS = ['tier-1', 'tier-2', 'customer-facing', 'internal', 'pci-dss', 'gdpr']

export function EditGroupDialog({
  open,
  onOpenChange,
  group,
  onSubmit,
  isSubmitting = false,
}: EditGroupDialogProps) {
  const [formData, setFormData] = useState<EditGroupFormData>({
    name: '',
    description: '',
    environment: 'production',
    criticality: 'medium',
    businessUnit: '',
    owner: '',
    ownerEmail: '',
    tags: [],
  })
  const [tagInput, setTagInput] = useState('')
  const [businessContextOpen, setBusinessContextOpen] = useState(false)
  const [membersOpen, setMembersOpen] = useState(false)
  const { t } = useTranslation()

  // Sync form data when group changes or dialog opens
  useEffect(() => {
    if (open && group) {
      setFormData({
        name: group.name,
        description: group.description || '',
        environment: group.environment as Environment,
        criticality: group.criticality as Criticality,
        businessUnit: group.businessUnit || '',
        owner: group.owner || '',
        ownerEmail: group.ownerEmail || '',
        tags: group.tags || [],
      })
      // Auto-expand business context if has data
      setBusinessContextOpen(
        !!(group.businessUnit || group.owner || group.ownerEmail || group.tags?.length)
      )
    }
  }, [open, group])

  const handleAddTag = useCallback(
    (tag: string) => {
      const normalizedTag = tag.trim().toLowerCase()
      if (normalizedTag && !formData.tags.includes(normalizedTag)) {
        setFormData((prev) => ({ ...prev, tags: [...prev.tags, normalizedTag] }))
      }
      setTagInput('')
    },
    [formData.tags]
  )

  const handleRemoveTag = useCallback((tagToRemove: string) => {
    setFormData((prev) => ({
      ...prev,
      tags: prev.tags.filter((x) => x !== tagToRemove),
    }))
  }, [])

  const handleTagKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter' || e.key === ',') {
        e.preventDefault()
        handleAddTag(tagInput)
      }
    },
    [tagInput, handleAddTag]
  )

  const handleSubmit = async () => {
    await onSubmit(formData)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        {/* Header */}
        <DialogHeader className="bg-gradient-to-r from-primary/10 via-primary/5 to-background">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 ring-1 ring-primary/20">
                <Pencil className="h-5 w-5 text-primary" />
              </div>
              <div>
                <DialogTitle className="text-lg">
                  {t('assetGroups.edit.title', 'Edit asset group')}
                </DialogTitle>
                <DialogDescription className="text-sm">
                  {t('assetGroups.edit.description', 'Update group details and business context')}
                </DialogDescription>
              </div>
            </div>
          </div>
        </DialogHeader>

        {/* Content */}
        <DialogBody className="p-0">
          <div className="space-y-4 p-6">
            {/* Group Identity */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <div className="h-7 w-7 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Building2 className="h-3.5 w-3.5 text-primary" />
                  </div>
                  {t('assetGroups.basic.identity', 'Group identity')}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="edit-name" className="text-sm">
                    {t('assetGroups.edit.name', 'Name')} <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="edit-name"
                    placeholder={t(
                      'assetGroups.basic.namePlaceholder',
                      'e.g., Payment Gateway Services'
                    )}
                    value={formData.name}
                    onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                    disabled={isSubmitting}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="edit-description" className="text-sm">
                    {t('assetGroups.basic.description', 'Description')}
                  </Label>
                  <Textarea
                    id="edit-description"
                    placeholder={t(
                      'assetGroups.edit.descriptionPlaceholder',
                      'Describe the purpose and scope...'
                    )}
                    value={formData.description}
                    onChange={(e) =>
                      setFormData((prev) => ({ ...prev, description: e.target.value }))
                    }
                    rows={2}
                    className="resize-none"
                    disabled={isSubmitting}
                  />
                </div>
              </CardContent>
            </Card>

            {/* Environment Selector */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">
                  {t('assetGroups.bulk.environment', 'Environment')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-4 gap-2">
                  {ENVIRONMENTS.map((env) => {
                    const Icon = env.icon
                    const isSelected = formData.environment === env.value
                    return (
                      <button
                        key={env.value}
                        type="button"
                        onClick={() => setFormData((prev) => ({ ...prev, environment: env.value }))}
                        disabled={isSubmitting}
                        className={cn(
                          'flex flex-col items-center gap-1.5 rounded-lg border-2 p-2.5 transition-all',
                          isSelected
                            ? cn(env.color, 'border-current ring-1 ring-current/20')
                            : 'border-muted bg-muted/30 hover:bg-muted/50 text-muted-foreground hover:text-foreground',
                          isSubmitting && 'opacity-50 cursor-not-allowed'
                        )}
                      >
                        <Icon className={cn('h-4 w-4', isSelected && 'text-foreground')} />
                        <span className="text-xs font-medium">{t(env.labelKey)}</span>
                      </button>
                    )
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Criticality Selector */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">
                  {t('assetGroups.bulk.criticality', 'Criticality')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2">
                  {CRITICALITIES.map((crit) => {
                    const Icon = crit.icon
                    const isSelected = formData.criticality === crit.value
                    return (
                      <button
                        key={crit.value}
                        type="button"
                        onClick={() =>
                          setFormData((prev) => ({ ...prev, criticality: crit.value }))
                        }
                        disabled={isSubmitting}
                        className={cn(
                          'flex items-start gap-2.5 rounded-lg border-2 p-2.5 text-start transition-all',
                          isSelected
                            ? cn(crit.bgColor, 'ring-1 ring-current/20')
                            : 'border-muted hover:border-muted-foreground/30',
                          isSubmitting && 'opacity-50 cursor-not-allowed'
                        )}
                      >
                        <div
                          className={cn(
                            'mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full',
                            isSelected ? crit.color : 'text-muted-foreground'
                          )}
                        >
                          <Icon className="h-3.5 w-3.5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div
                            className={cn(
                              'font-medium text-sm',
                              isSelected ? crit.color : 'text-foreground'
                            )}
                          >
                            {t(crit.labelKey)}
                          </div>
                          <div className="text-xs text-muted-foreground break-words">
                            {t(crit.descriptionKey)}
                          </div>
                        </div>
                        {isSelected && (
                          <div
                            className={cn('h-2 w-2 rounded-full shrink-0 mt-1', 'bg-foreground')}
                          />
                        )}
                      </button>
                    )
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Business Context - Collapsible */}
            <Collapsible open={businessContextOpen} onOpenChange={setBusinessContextOpen}>
              <Card>
                <CollapsibleTrigger asChild>
                  <CardHeader className="pb-3 cursor-pointer hover:bg-muted/50 transition-colors rounded-t-lg">
                    <CardTitle className="text-sm font-medium flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="h-7 w-7 rounded-lg bg-muted flex items-center justify-center">
                          <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
                        </div>
                        {t('assetGroups.basic.businessContext', 'Business context')}
                        <Badge variant="outline" className="ms-2 text-xs font-normal">
                          {t('assetGroups.basic.optional', 'Optional')}
                        </Badge>
                      </div>
                      <ChevronDown
                        className={cn(
                          'h-4 w-4 text-muted-foreground transition-transform duration-200',
                          businessContextOpen && 'rotate-180'
                        )}
                      />
                    </CardTitle>
                  </CardHeader>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <CardContent className="space-y-4 pt-0">
                    {/* Business Unit */}
                    <div className="space-y-2">
                      <Label className="text-sm flex items-center gap-2">
                        <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
                        {t('assetGroups.detail.info.businessUnit', 'Business unit')}
                      </Label>
                      <BusinessUnitField
                        value={formData.businessUnit}
                        onChange={(businessUnit) =>
                          setFormData((prev) => ({ ...prev, businessUnit }))
                        }
                        disabled={isSubmitting}
                      />
                    </div>

                    {/* Owner & Email */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-2">
                        <Label className="text-sm flex items-center gap-2">
                          <User className="h-3.5 w-3.5 text-muted-foreground" />
                          {t('assetGroups.detail.owner', 'Owner')}
                        </Label>
                        <Input
                          placeholder={t(
                            'assetGroups.basic.ownerPlaceholder',
                            'e.g., Nguyen Van A'
                          )}
                          value={formData.owner}
                          onChange={(e) =>
                            setFormData((prev) => ({ ...prev, owner: e.target.value }))
                          }
                          disabled={isSubmitting}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-sm flex items-center gap-2">
                          <Mail className="h-3.5 w-3.5 text-muted-foreground" />
                          {t('assetGroups.edit.email', 'Email')}
                        </Label>
                        <Input
                          type="email"
                          placeholder={t(
                            'assetGroups.basic.ownerEmailPlaceholder',
                            'e.g., a.nguyen@example.com.vn'
                          )}
                          value={formData.ownerEmail}
                          onChange={(e) =>
                            setFormData((prev) => ({
                              ...prev,
                              ownerEmail: e.target.value,
                            }))
                          }
                          disabled={isSubmitting}
                        />
                      </div>
                    </div>

                    {/* Tags */}
                    <div className="space-y-2">
                      <Label className="text-sm flex items-center gap-2">
                        <Tags className="h-3.5 w-3.5 text-muted-foreground" />
                        {t('assetGroups.detail.tags', 'Tags')}
                      </Label>
                      {formData.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 p-2 bg-muted/30 rounded-lg">
                          {formData.tags.map((tag) => (
                            <Badge
                              key={tag}
                              variant="secondary"
                              className="gap-1 ps-2 pe-1 text-xs"
                            >
                              {tag}
                              <button
                                type="button"
                                onClick={() => handleRemoveTag(tag)}
                                disabled={isSubmitting}
                                className="ms-0.5 rounded-full p-0.5 hover:bg-destructive/20 hover:text-destructive transition-colors"
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </Badge>
                          ))}
                        </div>
                      )}
                      <Input
                        placeholder={t(
                          'assetGroups.basic.tagPlaceholder',
                          'Type a tag and press Enter...'
                        )}
                        value={tagInput}
                        onChange={(e) => setTagInput(e.target.value)}
                        onKeyDown={handleTagKeyDown}
                        disabled={isSubmitting}
                      />
                      <div className="flex flex-wrap gap-1">
                        <span className="text-xs text-muted-foreground me-1 py-0.5">
                          {t('assetGroups.basic.quickAdd', 'Quick add:')}
                        </span>
                        {SUGGESTED_TAGS.filter((tg) => !formData.tags.includes(tg))
                          .slice(0, 4)
                          .map((tag) => (
                            <Badge
                              key={tag}
                              variant="outline"
                              className={cn(
                                'cursor-pointer hover:bg-primary/10 hover:text-primary hover:border-primary/30 text-xs transition-colors',
                                isSubmitting && 'pointer-events-none opacity-50'
                              )}
                              onClick={() => handleAddTag(tag)}
                            >
                              + {tag}
                            </Badge>
                          ))}
                      </div>
                    </div>
                  </CardContent>
                </CollapsibleContent>
              </Card>
            </Collapsible>

            {/* Members: the rule that fills the group, and a pasted list */}
            <Collapsible open={membersOpen} onOpenChange={setMembersOpen}>
              <Card>
                <CollapsibleTrigger asChild>
                  <CardHeader className="pb-3 cursor-pointer hover:bg-muted/50 transition-colors rounded-t-lg">
                    <CardTitle className="text-sm font-medium flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="h-7 w-7 rounded-lg bg-muted flex items-center justify-center">
                          <Server className="h-3.5 w-3.5 text-muted-foreground" />
                        </div>
                        {t('assetGroups.members.section', 'Members')}
                        {group.rule && (
                          <Badge variant="outline" className="ms-2 text-xs font-normal">
                            {t('assetGroups.members.automatic', 'Automatic')}
                          </Badge>
                        )}
                      </div>
                      <ChevronDown
                        className={cn(
                          'h-4 w-4 text-muted-foreground transition-transform duration-200',
                          membersOpen && 'rotate-180'
                        )}
                      />
                    </CardTitle>
                  </CardHeader>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <CardContent className="pt-0">
                    <GroupMembersSection group={group} />
                  </CardContent>
                </CollapsibleContent>
              </Card>
            </Collapsible>
          </div>
        </DialogBody>

        {/* Footer */}
        <DialogFooter className="bg-muted/30">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            {t('assetGroups.cancel', 'Cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={!formData.name.trim() || isSubmitting}>
            {isSubmitting ? (
              <>
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
                {t('assetGroups.edit.saving', 'Saving...')}
              </>
            ) : (
              t('assetGroups.edit.save', 'Save changes')
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
