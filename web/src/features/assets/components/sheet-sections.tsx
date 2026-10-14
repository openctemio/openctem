/**
 * Asset Detail Sheet - Helper Section Components
 *
 * Reusable UI sections for asset detail sheets
 */

import * as React from 'react'
import { Clock, Info, Tag as TagIcon, Trash2, Pencil, Save, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { TagInput } from '@/components/ui/tag-input'
import { cn } from '@/lib/utils'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailSection,
  DetailField,
  DetailFieldGrid,
  DangerZone,
  DangerZoneItem,
} from '@/features/shared'
import type { AssetType } from '../types/asset.types'
import { ASSET_TYPE_LABELS } from '../types/asset.types'

// ============================================
// Stat Card
// ============================================

interface StatCardProps {
  icon: React.ElementType
  iconBg: string
  iconColor: string
  value: string | number
  label: string
  className?: string
}

export function StatCard({
  icon: Icon,
  iconBg,
  iconColor,
  value,
  label,
  className,
}: StatCardProps) {
  return (
    <div className={cn('rounded-xl border p-4 bg-card', className)}>
      <div className="flex items-center gap-3">
        <div className={cn('h-10 w-10 rounded-lg flex items-center justify-center', iconBg)}>
          <Icon className={cn('h-5 w-5', iconColor)} />
        </div>
        <div>
          <p className="text-2xl font-bold">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </div>
    </div>
  )
}

// Centered variant for website-style stats
export function StatCardCentered({
  icon: Icon,
  iconBg,
  iconColor,
  value,
  label,
  className,
}: StatCardProps) {
  return (
    <div className={cn('rounded-xl border p-4 bg-card', className)}>
      <div className="flex flex-col items-center text-center">
        <div className={cn('h-10 w-10 rounded-lg flex items-center justify-center mb-2', iconBg)}>
          <Icon className={cn('h-5 w-5', iconColor)} />
        </div>
        <p className="text-xl font-bold">{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </div>
    </div>
  )
}

// ============================================
// Stats Grid
// ============================================

interface StatsGridProps {
  children: React.ReactNode
  columns?: 2 | 3
  className?: string
}

export function StatsGrid({ children, columns = 2, className }: StatsGridProps) {
  return (
    <div
      className={cn(
        'grid gap-3',
        columns === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-3',
        className
      )}
    >
      {children}
    </div>
  )
}

// ============================================
// Timeline Section
// ============================================

interface TimelineSectionProps {
  firstSeen: string
  lastSeen: string
  createdAt?: string
  updatedAt?: string
}

/**
 * Renders all 4 lifecycle timestamps an asset carries:
 *   - First seen — when the asset was first observed by any scanner
 *   - Last seen  — when the asset was last observed
 *   - Created    — when the asset row was inserted in OpenCTEM
 *   - Updated    — when the asset row was last modified
 *
 * First/last seen describe the *real-world discovery* lifecycle.
 * Created/updated describe the *database record* lifecycle. They can
 * differ — e.g. an asset was discovered yesterday (firstSeen) but the
 * description was edited today (updatedAt).
 */
export function TimelineSection({
  firstSeen,
  lastSeen,
  createdAt,
  updatedAt,
}: TimelineSectionProps) {
  const { t } = useTranslation()
  const fmt = (iso: string) => new Date(iso).toLocaleString()
  return (
    <DetailSection title={t('assets.sheetSections.timeline', 'Timeline')} icon={Clock}>
      <DetailFieldGrid>
        <DetailField label={t('assets.overview2.firstSeen', 'First seen')}>
          {fmt(firstSeen)}
        </DetailField>
        <DetailField label={t('components.col.lastSeen', 'Last seen')}>{fmt(lastSeen)}</DetailField>
        {createdAt && (
          <DetailField label={t('assets.sheetSections.created', 'Created')}>
            {fmt(createdAt)}
          </DetailField>
        )}
        {updatedAt && updatedAt !== createdAt && (
          <DetailField label={t('assets.sheetSections.updated', 'Updated')}>
            {fmt(updatedAt)}
          </DetailField>
        )}
      </DetailFieldGrid>
    </DetailSection>
  )
}

// ============================================
// Technical Details Section
// ============================================

interface TechnicalDetailsSectionProps {
  id: string
  type: AssetType
  groupId?: string // Optional - asset can be ungrouped
  subType?: string
  provider?: string
  /** ID in the source system (cloud provider, SCM, scanner). */
  externalId?: string
  /** Parent asset ID, e.g. the domain of a subdomain. */
  parentId?: string
}

export function TechnicalDetailsSection({
  id,
  type,
  groupId,
  subType,
  provider,
  externalId,
  parentId,
}: TechnicalDetailsSectionProps) {
  const { t } = useTranslation()
  return (
    <DetailSection title={t('assets.sheetSections.technical', 'Technical details')} icon={Info}>
      <DetailFieldGrid>
        <DetailField label={t('assets.properties.columns.type', 'Type')}>
          {ASSET_TYPE_LABELS[type] ?? type}
        </DetailField>
        <DetailField label={t('assets.sheetSections.subType', 'Sub-type')}>{subType}</DetailField>
        {provider && provider !== 'other' && (
          <DetailField label={t('assets.sheetSections.provider', 'Provider')}>
            {provider}
          </DetailField>
        )}
        <DetailField label={t('assets.sheetSections.group', 'Group')}>
          {groupId ? (
            <code className="font-mono text-xs break-all">{groupId}</code>
          ) : (
            <span className="text-muted-foreground">
              {t('assets.sheetSections.ungrouped', 'Ungrouped')}
            </span>
          )}
        </DetailField>
        <DetailField label={t('assets.sheetSections.id', 'ID')} full>
          <code className="font-mono text-xs break-all">{id}</code>
        </DetailField>
        <DetailField label={t('assets.sheetSections.externalId', 'External ID')} full>
          {externalId ? (
            <code className="font-mono text-xs break-all">{externalId}</code>
          ) : undefined}
        </DetailField>
        <DetailField label={t('assets.sheetSections.parent', 'Parent asset')} full>
          {parentId ? <code className="font-mono text-xs break-all">{parentId}</code> : undefined}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

// ============================================
// Danger Zone Section
// ============================================

interface DangerZoneSectionProps {
  onDelete: () => void
  assetTypeName: string
}

/** The shared DangerZone, for asset detail sheets. */
export function DangerZoneSection({ onDelete, assetTypeName }: DangerZoneSectionProps) {
  const { t } = useTranslation()
  const noun = assetTypeName.toLowerCase()
  return (
    <DangerZone as="h3">
      <DangerZoneItem
        title={t('assets.sheetSections.deleteTitle', 'Delete {noun}', { noun })}
        description={t(
          'assets.sheetSections.deleteDesc',
          'Permanently delete this {noun} from your inventory.',
          { noun }
        )}
        action={
          <Button variant="destructive" size="sm" onClick={onDelete}>
            <Trash2 className="me-2 h-4 w-4" />
            {t('assets.sheetSections.deleteTitle', 'Delete {noun}', { noun })}
          </Button>
        }
      />
    </DangerZone>
  )
}

// ============================================
// Metadata Grid
// ============================================

interface MetadataGridProps {
  children: React.ReactNode
  columns?: 1 | 2
  className?: string
}

/** Label/value grid. A thin wrapper over the shared DetailFieldGrid (no card). */
export function MetadataGrid({ children, columns = 2, className }: MetadataGridProps) {
  return (
    <DetailFieldGrid className={cn(columns === 1 && 'sm:grid-cols-1', className)}>
      {children}
    </DetailFieldGrid>
  )
}

// ============================================
// Metadata Row
// ============================================

interface MetadataRowProps {
  label: string
  value?: string | number | null
  children?: React.ReactNode
  colSpan?: 1 | 2
}

export function MetadataRow({ label, value, children, colSpan }: MetadataRowProps) {
  if (!value && !children) return null

  return (
    <DetailField label={label} full={colSpan === 2}>
      {children || value}
    </DetailField>
  )
}

// ============================================
// Tags Section
// ============================================

interface TagsSectionProps {
  tags?: string[]
  suggestions?: string[]
  onSave?: (tags: string[]) => Promise<void>
  className?: string
  /** Clicking a tag toggles it in the list's filter; without it tags are plain badges. */
  onTagClick?: (tag: string) => void
  /** The tags the list is filtered by (shown as active). */
  activeTags?: string[]
}

export function TagsSection({
  tags,
  suggestions,
  onSave,
  className,
  onTagClick,
  activeTags,
}: TagsSectionProps) {
  const { t } = useTranslation()
  const [editing, setEditing] = React.useState(false)
  const [editTags, setEditTags] = React.useState<string[]>([])
  const [saving, setSaving] = React.useState(false)

  const startEditing = () => {
    setEditTags(tags || [])
    setEditing(true)
  }

  const cancelEditing = () => {
    setEditing(false)
    setEditTags([])
  }

  const handleSave = async () => {
    if (!onSave) return
    setSaving(true)
    try {
      await onSave(editTags)
      setEditing(false)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <DetailSection
      title={t('assets.tagFilter.title', 'Tags')}
      icon={TagIcon}
      className={className}
      actions={
        <>
          {onSave && !editing && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 w-7 p-0"
              aria-label={t('assets.sheetSections.editTags', 'Edit tags')}
              onClick={startEditing}
            >
              <Pencil className="h-3.5 w-3.5" />
            </Button>
          )}
          {editing && (
            <>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                aria-label={t('assets.sheetSections.saveTags', 'Save tags')}
                onClick={handleSave}
                disabled={saving}
              >
                <Save className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                aria-label={t('common.cancel', 'Cancel')}
                onClick={cancelEditing}
                disabled={saving}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
        </>
      }
    >
      {editing ? (
        <TagInput value={editTags} onChange={setEditTags} suggestions={suggestions} maxTags={20} />
      ) : tags && tags.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {tags.map((tag) => {
            if (!onTagClick) {
              return (
                <Badge key={tag} variant="secondary">
                  {tag}
                </Badge>
              )
            }
            const active = activeTags?.includes(tag) ?? false
            return (
              <button
                key={tag}
                type="button"
                onClick={() => onTagClick(tag)}
                aria-pressed={active}
                title={
                  active
                    ? t('assets.tagFilter.chipRemove', 'Remove "{tag}" from the filter', { tag })
                    : t('assets.tagFilter.chipAdd', 'Filter the list by "{tag}"', { tag })
                }
                className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <Badge variant={active ? 'default' : 'secondary'} className="cursor-pointer">
                  {tag}
                </Badge>
              </button>
            )
          })}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          {t('assets.sheetSections.noTags', 'No tags')}
        </p>
      )}
    </DetailSection>
  )
}

// ============================================
// Section Title
// ============================================

interface SectionTitleProps {
  children: React.ReactNode
  className?: string
}

export function SectionTitle({ children, className }: SectionTitleProps) {
  return <h3 className={cn('text-sm font-semibold mb-3', className)}>{children}</h3>
}
