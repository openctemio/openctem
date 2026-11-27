/**
 * Basic Info Step
 *
 * First step for entering group name, description, environment, criticality,
 * and business context (CTEM Scoping)
 *
 * Redesigned with card-based layout and visual selectors
 */

'use client'

import { useState, useCallback } from 'react'
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
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { BusinessUnitField } from '../business-unit-field'
import type { CreateGroupFormData } from './types'
import type { Environment, Criticality } from '@/features/shared/types'

interface BasicInfoStepProps {
  data: CreateGroupFormData
  onChange: (data: Partial<CreateGroupFormData>) => void
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
    descriptionKey: 'assetGroups.basic.crit.criticalDesc',
    icon: AlertTriangle,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
  {
    value: 'high',
    labelKey: 'assetGroups.basic.crit.high',
    descriptionKey: 'assetGroups.basic.crit.highDesc',
    icon: AlertCircle,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
  {
    value: 'medium',
    labelKey: 'assetGroups.basic.crit.medium',
    descriptionKey: 'assetGroups.basic.crit.mediumDesc',
    icon: Info,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
  {
    value: 'low',
    labelKey: 'assetGroups.basic.crit.low',
    descriptionKey: 'assetGroups.basic.crit.lowDesc',
    icon: MinusCircle,
    color: 'text-foreground',
    bgColor: 'border-primary bg-primary/5',
  },
]

const SUGGESTED_TAGS = [
  'tier-1',
  'tier-2',
  'tier-3',
  'customer-facing',
  'internal',
  'pci-dss',
  'gdpr',
  'hipaa',
  'soc2',
  'infrastructure',
  'application',
  'database',
  'api',
  'legacy',
]

export function BasicInfoStep({ data, onChange }: BasicInfoStepProps) {
  const { t } = useTranslation()
  const [tagInput, setTagInput] = useState('')
  const [businessContextOpen, setBusinessContextOpen] = useState(true)

  const handleAddTag = useCallback(
    (tag: string) => {
      const normalizedTag = tag.trim().toLowerCase()
      if (normalizedTag && !data.tags.includes(normalizedTag)) {
        onChange({ tags: [...data.tags, normalizedTag] })
      }
      setTagInput('')
    },
    [data.tags, onChange]
  )

  const handleRemoveTag = useCallback(
    (tagToRemove: string) => {
      onChange({ tags: data.tags.filter((x) => x !== tagToRemove) })
    },
    [data.tags, onChange]
  )

  const handleTagKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter' || e.key === ',') {
        e.preventDefault()
        handleAddTag(tagInput)
      }
    },
    [tagInput, handleAddTag]
  )

  return (
    <div className="space-y-4 p-6">
      {/* Group Identity Card */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center">
              <Building2 className="h-4 w-4 text-primary" />
            </div>
            {t('assetGroups.basic.identity', 'Group identity')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Group Name */}
          <div className="space-y-2">
            <Label htmlFor="name" className="text-sm">
              {t('assetGroups.basic.name', 'Group name')}{' '}
              <span className="text-destructive">*</span>
            </Label>
            <Input
              id="name"
              placeholder={t('assetGroups.basic.namePlaceholder', 'e.g., Payment Gateway Services')}
              value={data.name}
              onChange={(e) => onChange({ name: e.target.value })}
            />
          </div>

          {/* Description */}
          <div className="space-y-2">
            <Label htmlFor="description" className="text-sm">
              {t('assetGroups.basic.description', 'Description')}
            </Label>
            <Textarea
              id="description"
              placeholder={t(
                'assetGroups.basic.descriptionPlaceholder',
                'Describe the purpose and scope of this asset group...'
              )}
              value={data.description}
              onChange={(e) => onChange({ description: e.target.value })}
              rows={2}
              className="resize-none"
            />
          </div>
        </CardContent>
      </Card>

      {/* Environment Selector */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium">
            {t('assetGroups.bulk.environment', 'Environment')}{' '}
            <span className="text-destructive">*</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {ENVIRONMENTS.map((env) => {
              const Icon = env.icon
              const isSelected = data.environment === env.value
              return (
                <button
                  key={env.value}
                  type="button"
                  onClick={() => onChange({ environment: env.value })}
                  className={cn(
                    'flex flex-col items-center gap-1.5 rounded-lg border-2 p-3 transition-all',
                    isSelected
                      ? cn(env.color, 'border-current ring-1 ring-current/20')
                      : 'border-muted bg-muted/30 hover:bg-muted/50 text-muted-foreground hover:text-foreground'
                  )}
                >
                  <Icon className={cn('h-5 w-5', isSelected && 'text-foreground')} />
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
            {t('assetGroups.bulk.criticality', 'Criticality')}{' '}
            <span className="text-destructive">*</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {CRITICALITIES.map((crit) => {
              const Icon = crit.icon
              const isSelected = data.criticality === crit.value
              return (
                <button
                  key={crit.value}
                  type="button"
                  onClick={() => onChange({ criticality: crit.value })}
                  className={cn(
                    'flex items-start gap-3 rounded-lg border-2 p-3 text-start transition-all',
                    isSelected
                      ? cn(crit.bgColor, 'ring-1 ring-current/20')
                      : 'border-muted hover:border-muted-foreground/30'
                  )}
                >
                  <div
                    className={cn(
                      'mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full',
                      isSelected ? crit.color : 'text-muted-foreground'
                    )}
                  >
                    <Icon className="h-4 w-4" />
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
                    <div className={cn('h-2 w-2 rounded-full shrink-0 mt-1.5', 'bg-foreground')} />
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
                  <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center">
                    <Building2 className="h-4 w-4 text-muted-foreground" />
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
                <Label htmlFor="businessUnit" className="text-sm flex items-center gap-2">
                  <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
                  {t('assetGroups.detail.info.businessUnit', 'Business unit')}
                </Label>
                <BusinessUnitField
                  value={data.businessUnit}
                  onChange={(businessUnit) => onChange({ businessUnit })}
                  max={6}
                />
              </div>

              {/* Owner & Email */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="owner" className="text-sm flex items-center gap-2">
                    <User className="h-3.5 w-3.5 text-muted-foreground" />
                    {t('assetGroups.detail.owner', 'Owner')}
                  </Label>
                  <Input
                    id="owner"
                    placeholder={t('assetGroups.basic.ownerPlaceholder', 'e.g., Nguyen Van A')}
                    value={data.owner}
                    onChange={(e) => onChange({ owner: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="ownerEmail" className="text-sm flex items-center gap-2">
                    <Mail className="h-3.5 w-3.5 text-muted-foreground" />
                    {t('assetGroups.basic.ownerEmail', 'Owner email')}
                  </Label>
                  <Input
                    id="ownerEmail"
                    type="email"
                    placeholder={t(
                      'assetGroups.basic.ownerEmailPlaceholder',
                      'e.g., a.nguyen@example.com.vn'
                    )}
                    value={data.ownerEmail}
                    onChange={(e) => onChange({ ownerEmail: e.target.value })}
                  />
                </div>
              </div>

              {/* Tags */}
              <div className="space-y-2">
                <Label className="text-sm flex items-center gap-2">
                  <Tags className="h-3.5 w-3.5 text-muted-foreground" />
                  {t('assetGroups.detail.tags', 'Tags')}
                </Label>
                {data.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 p-2 bg-muted/30 rounded-lg">
                    {data.tags.map((tag) => (
                      <Badge key={tag} variant="secondary" className="gap-1 ps-2 pe-1">
                        {tag}
                        <button
                          type="button"
                          onClick={() => handleRemoveTag(tag)}
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
                />
                <div className="flex flex-wrap gap-1">
                  <span className="text-xs text-muted-foreground me-1 py-0.5">
                    {t('assetGroups.basic.quickAdd', 'Quick add:')}
                  </span>
                  {SUGGESTED_TAGS.filter((x) => !data.tags.includes(x))
                    .slice(0, 6)
                    .map((tag) => (
                      <Badge
                        key={tag}
                        variant="outline"
                        className="cursor-pointer hover:bg-primary/10 hover:text-primary hover:border-primary/30 text-xs transition-colors"
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
    </div>
  )
}
