'use client'

/**
 * One menu to switch dashboards: "Organization" (only for viewers the server
 * lists organization dashboards for) and "Mine", with search once there are
 * many, plus New and Manage.
 */

import { useMemo, useState } from 'react'
import { Building2, Check, ChevronDown, LayoutGrid, Plus, Star, User } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import type { Dashboard } from '../api/dashboards.types'
import type { DashboardRef } from '../landing'

/** Search shows once the two lists hold more than this many dashboards. */
export const SWITCHER_SEARCH_FROM = 8

export interface DashboardSwitcherProps {
  personal: readonly Dashboard[]
  /** Undefined: the viewer cannot read organization dashboards (group hidden). */
  organization?: readonly Dashboard[]
  active: DashboardRef | null
  /** Label of the active entry when it is not a stored dashboard. */
  fallbackLabel?: string
  onChoose: (ref: DashboardRef) => void
  /** Extra entries (built-in views) rendered after the two groups. */
  extra?: React.ReactNode
}

export function DashboardSwitcher({
  personal,
  organization,
  active,
  fallbackLabel,
  onChoose,
  extra,
}: DashboardSwitcherProps) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const total = personal.length + (organization?.length ?? 0)
  const q = query.trim().toLowerCase()
  const match = useMemo(() => (d: Dashboard) => !q || d.name.toLowerCase().includes(q), [q])
  const activeDashboard =
    active &&
    (active.kind === 'personal' ? personal : (organization ?? [])).find((d) => d.id === active.id)
  const label = activeDashboard?.name ?? fallbackLabel ?? t('dashboards.title', 'Dashboard')

  const entry = (kind: DashboardRef['kind'], d: Dashboard) => {
    const isActive = active?.kind === kind && active.id === d.id
    const isDefault = kind === 'personal' ? d.is_default : d.is_org_default
    return (
      <DropdownMenuItem
        key={`${kind}:${d.id}`}
        onSelect={() => onChoose({ kind, id: d.id })}
        aria-current={isActive ? 'true' : undefined}
      >
        <span className="flex-1 truncate">{d.name}</span>
        {isDefault && (
          <Star
            className="me-1 h-3.5 w-3.5 text-muted-foreground"
            aria-label={t('dashboards.switcher.default', 'Default')}
          />
        )}
        {isActive && <Check className="h-4 w-4" aria-hidden />}
      </DropdownMenuItem>
    )
  }

  const org = (organization ?? []).filter(match)
  const mine = personal.filter(match)

  return (
    <DropdownMenu onOpenChange={(open) => !open && setQuery('')}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="max-w-[16rem]"
          aria-label={t('dashboards.switcher.label', 'Switch dashboard: {name}', { name: label })}
        >
          <LayoutGrid className="me-2 h-4 w-4 shrink-0" aria-hidden />
          <span className="truncate">{label}</span>
          <ChevronDown className="ms-2 h-4 w-4 shrink-0" aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        {total > SWITCHER_SEARCH_FROM && (
          <div className="p-1" onKeyDown={(e) => e.stopPropagation()}>
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('dashboards.switcher.search', 'Search dashboards')}
              aria-label={t('dashboards.switcher.search', 'Search dashboards')}
              className="h-8"
            />
          </div>
        )}
        {organization !== undefined && (
          <DropdownMenuGroup>
            <DropdownMenuLabel className="flex items-center gap-1.5">
              <Building2 className="h-3.5 w-3.5" aria-hidden />
              {t('dashboards.switcher.organization', 'Organization')}
            </DropdownMenuLabel>
            {org.length === 0 ? (
              <DropdownMenuItem disabled>
                {q
                  ? t('dashboards.switcher.noMatch', 'No dashboard matches')
                  : t('dashboards.switcher.noOrganization', 'No organization dashboards yet')}
              </DropdownMenuItem>
            ) : (
              org.map((d) => entry('organization', d))
            )}
            <DropdownMenuSeparator />
          </DropdownMenuGroup>
        )}
        <DropdownMenuGroup>
          <DropdownMenuLabel className="flex items-center gap-1.5">
            <User className="h-3.5 w-3.5" aria-hidden />
            {t('dashboards.switcher.mine', 'Mine')}
          </DropdownMenuLabel>
          {mine.length === 0 ? (
            <DropdownMenuItem disabled>
              {q
                ? t('dashboards.switcher.noMatch', 'No dashboard matches')
                : t('dashboards.switcher.noPersonal', 'No dashboards of your own yet')}
            </DropdownMenuItem>
          ) : (
            mine.map((d) => entry('personal', d))
          )}
        </DropdownMenuGroup>
        {extra}
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/dashboards">
            <Plus className="me-2 h-4 w-4" aria-hidden />
            {t('dashboards.switcher.new', 'New dashboard')}
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/dashboards">
            <LayoutGrid className="me-2 h-4 w-4" aria-hidden />
            {t('dashboards.switcher.manage', 'Manage dashboards')}
          </Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
