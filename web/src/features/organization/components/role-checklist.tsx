'use client'

import { useId, useState } from 'react'
import { ChevronDown, Plus, Shield } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { RoleRiskBadge, RoleSummaryLine } from '@/features/access-control/components/role-risk'
import type { Role } from '@/features/access-control/types/role.types'

export type RoleChecklistItem = Pick<
  Role,
  'id' | 'name' | 'slug' | 'description' | 'is_system' | 'permission_count'
> &
  Partial<Pick<Role, 'summary'>>

interface RoleChecklistProps {
  roles: RoleChecklistItem[]
  selected: string[]
  onChange: (next: string[]) => void
  loading?: boolean
  disabled?: boolean
  /** Upper bound on how many roles may be selected. */
  max?: number
  /**
   * Whether the caller may make someone an administrator. Only the owner may
   * (settings decision B2); for everyone else the system admin role is left
   * out of the picker unless it is already selected, so an administrator
   * editing their own roles can keep it.
   */
  canGrantAdmin?: boolean
  className?: string
}

/**
 * The picker hides the owner role (ownership is not assigned through roles)
 * and junk rows, and the system admin role from anyone but the owner, unless
 * it is already in `keep` (the current selection).
 */
export function selectableRoles<T extends RoleChecklistItem>(
  roles: T[],
  opts: { canGrantAdmin?: boolean; keep?: string[] } = {}
): T[] {
  return roles.filter(
    (r) =>
      r.slug !== 'owner' &&
      r.id &&
      typeof r.name === 'string' &&
      r.name.length > 0 &&
      (r.slug !== 'admin' || !r.is_system || opts.canGrantAdmin || opts.keep?.includes(r.id))
  )
}

/** System roles from least to most privileged, then custom roles by name. */
function ordered<T extends RoleChecklistItem>(roles: T[]): T[] {
  const rank: Record<string, number> = { viewer: 0, member: 1, admin: 2 }
  return [...roles].sort((a, b) => {
    if (a.is_system !== b.is_system) return a.is_system ? -1 : 1
    if (a.is_system) return (rank[a.slug] ?? 9) - (rank[b.slug] ?? 9)
    return a.name.localeCompare(b.name)
  })
}

function RoleText({ role, descId }: { role: RoleChecklistItem; descId: string }) {
  const name = role.name.slice(0, 100)
  return (
    <div className="min-w-0 flex-1">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        <span className="truncate text-sm font-medium" title={role.name}>
          {name}
        </span>
        {role.summary && <RoleRiskBadge risk={role.summary.risk} />}
      </div>
      <div id={descId}>
        {role.description && (
          <p className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">
            {role.description.slice(0, 200)}
          </p>
        )}
        <RoleSummaryLine summary={role.summary} className="mt-1" />
      </div>
    </div>
  )
}

// Cards keep their focus ring and border inside the list: the list pads
// itself, so nothing is clipped by a scrolling parent.
const cardClass = (selected: boolean, disabled: boolean) =>
  cn(
    'flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors',
    'has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring/50',
    selected ? 'border-primary bg-primary/5' : 'border-border bg-card hover:bg-muted/50',
    disabled && 'cursor-not-allowed opacity-60'
  )

function GroupTitle({ title }: { title: string }) {
  return (
    <div className="mb-2 flex items-center gap-2">
      <span className="text-xs font-medium text-muted-foreground">{title}</span>
      <div className="h-px flex-1 bg-border" />
    </div>
  )
}

function CheckGroup({
  title,
  roles,
  selected,
  toggle,
  disabled,
  atMax,
}: {
  title: string
  roles: RoleChecklistItem[]
  selected: string[]
  toggle: (id: string) => void
  disabled?: boolean
  atMax: boolean
}) {
  const base = useId()
  if (roles.length === 0) return null
  return (
    <div role="group" aria-label={title}>
      <GroupTitle title={title} />
      <div className="space-y-2">
        {roles.map((role) => {
          const isSelected = selected.includes(role.id)
          const itemDisabled = Boolean(disabled || (atMax && !isSelected))
          const descId = `${base}-${role.id}-desc`
          return (
            <label key={role.id} className={cardClass(isSelected, itemDisabled)}>
              <Checkbox
                className="mt-0.5"
                checked={isSelected}
                disabled={itemDisabled}
                onCheckedChange={() => toggle(role.id)}
                aria-label={role.name.slice(0, 100)}
                aria-describedby={descId}
              />
              <RoleText role={role} descId={descId} />
            </label>
          )
        })}
      </div>
    </div>
  )
}

function Loading({ className }: { className?: string }) {
  return (
    <div className={cn('space-y-2', className)}>
      {[1, 2, 3].map((i) => (
        <Skeleton key={i} className="h-14 w-full rounded-lg" />
      ))}
    </div>
  )
}

function Empty({ className }: { className?: string }) {
  const { t } = useTranslation()
  return (
    <div className={cn('py-6 text-center', className)}>
      <Shield className="mx-auto mb-2 h-10 w-10 text-muted-foreground/30" aria-hidden="true" />
      <p className="text-sm text-muted-foreground">{t('org.rolePicker.none')}</p>
      <p className="mt-1 text-xs text-muted-foreground">{t('org.rolePicker.noneHint')}</p>
    </div>
  )
}

/**
 * The multi-select role list used to change someone's complete role set.
 * System roles first, then custom roles; each shows its risk and what it
 * does instead of a permission count.
 */
export function RoleChecklist({
  roles,
  selected,
  onChange,
  loading,
  disabled,
  max,
  canGrantAdmin = false,
  className,
}: RoleChecklistProps) {
  const { t } = useTranslation()
  if (loading) return <Loading className={className} />
  const available = ordered(selectableRoles(roles, { canGrantAdmin, keep: selected }))
  if (available.length === 0) return <Empty className={className} />

  const atMax = max !== undefined && selected.length >= max
  const toggle = (id: string) =>
    onChange(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id])

  return (
    <div className={cn('space-y-4 p-0.5', className)}>
      <CheckGroup
        title={t('org.rolePicker.systemRoles')}
        roles={available.filter((r) => r.is_system)}
        selected={selected}
        toggle={toggle}
        disabled={disabled}
        atMax={atMax}
      />
      <CheckGroup
        title={t('org.rolePicker.customRoles')}
        roles={available.filter((r) => !r.is_system)}
        selected={selected}
        toggle={toggle}
        disabled={disabled}
        atMax={atMax}
      />
    </div>
  )
}

/**
 * One primary role, plus optional additional roles (api RFC-095 §6). The
 * primary role defines the person (viewer, member, administrator, or a custom
 * role); additional custom roles add to it. `selected[0]` is the primary role.
 */
export function RolePicker({
  roles,
  selected,
  onChange,
  loading,
  disabled,
  max = 10,
  canGrantAdmin = false,
  className,
}: RoleChecklistProps) {
  const { t } = useTranslation()
  const base = useId()
  const [showMore, setShowMore] = useState(selected.length > 1)
  if (loading) return <Loading className={className} />
  const available = ordered(selectableRoles(roles, { canGrantAdmin, keep: selected }))
  if (available.length === 0) return <Empty className={className} />

  const primary = selected[0] ?? ''
  const extra = selected.slice(1)
  const extraOptions = available.filter((r) => !r.is_system && r.id !== primary)
  const setPrimary = (id: string) => onChange([id, ...extra.filter((x) => x !== id)])
  const toggleExtra = (id: string) => {
    const next = extra.includes(id) ? extra.filter((x) => x !== id) : [...extra, id]
    onChange(primary ? [primary, ...next] : next)
  }

  return (
    <div className={cn('space-y-4 p-0.5', className)}>
      <RadioGroup
        value={primary}
        onValueChange={setPrimary}
        disabled={disabled}
        aria-label={t('org.rolePicker.primary')}
        className="gap-2"
      >
        {available.map((role) => {
          const descId = `${base}-${role.id}-desc`
          const itemId = `${base}-${role.id}`
          return (
            <label
              key={role.id}
              htmlFor={itemId}
              className={cardClass(primary === role.id, Boolean(disabled))}
            >
              <RadioGroupItem
                id={itemId}
                value={role.id}
                className="mt-0.5"
                aria-label={role.name.slice(0, 100)}
                aria-describedby={descId}
              />
              <RoleText role={role} descId={descId} />
            </label>
          )
        })}
      </RadioGroup>

      {extraOptions.length > 0 && (
        <div>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 px-2 text-xs"
            aria-expanded={showMore}
            onClick={() => setShowMore((v) => !v)}
          >
            {showMore ? (
              <ChevronDown className="me-1 size-3.5" aria-hidden="true" />
            ) : (
              <Plus className="me-1 size-3.5" aria-hidden="true" />
            )}
            {t('org.rolePicker.addAnother')}
            {extra.length > 0 && ` (${extra.length})`}
          </Button>
          {showMore && (
            <div className="mt-2">
              <CheckGroup
                title={t('org.rolePicker.additional')}
                roles={extraOptions}
                selected={extra}
                toggle={toggleExtra}
                disabled={disabled || !primary}
                atMax={selected.length >= max}
              />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/**
 * The system viewer role: the least-privilege default a new person starts
 * with. The inviter can change it before sending.
 */
export function defaultViewerRoleId(
  roles: Pick<RoleChecklistItem, 'id' | 'slug' | 'is_system'>[]
): string | undefined {
  return roles.find((r) => r.slug === 'viewer' && r.is_system)?.id
}
