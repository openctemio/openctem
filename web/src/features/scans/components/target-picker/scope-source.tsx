'use client'

/**
 * Scope source of the target picker: the organization's active in-scope
 * entries a scan can take (domains, wildcards, addresses, ranges), searched on
 * the server, each one a checkbox, plus "Add all in-scope entries". Read with
 * the caller's own session (GET /scope/targets, attack_surface:scope:read,
 * tenant from the session); the step shows this source only to people who
 * hold that permission. Out of scope entries are a separate list and never
 * read here. A picked entry becomes a typed target, so it still passes the
 * scope check like anything typed.
 */

import { useMemo, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useSearchQuery } from '@/hooks/use-search-query'
import { get } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { useScopeTargetsApi } from '@/features/scope/api/use-scope-api'
import type { ApiScopeTarget } from '@/features/scope/api/scope-api.types'
import { MAX_DIRECT_TARGETS } from '../../lib/scan-form'
import {
  expiresInDays,
  PICKABLE_SCOPE_TYPES,
  SCOPE_EXPIRY_WARN_DAYS,
  scopeEntryTarget,
} from '../../lib/scope-pick'
import { targetKey } from '../../lib/target-format'
import { PickerList } from './picker-list'

/** Entries listed at once (the API's largest page). */
export const SCOPE_PAGE_SIZE = 100

const TYPES = PICKABLE_SCOPE_TYPES.join(',')

interface ScopeSourceProps {
  /** Keys (targetKey) of the targets already in the scan. */
  present: ReadonlySet<string>
  onChange: (targets: string[], picked: boolean) => void
}

function pageURL(page: number, search: string): string {
  const params = new URLSearchParams({
    types: TYPES,
    statuses: 'active',
    per_page: String(SCOPE_PAGE_SIZE),
    page: String(page),
    sort_by: 'pattern',
    sort_order: 'asc',
  })
  if (search) params.set('search', search)
  return `/api/v1/scope/targets?${params}`
}

/** Every active pickable entry matching the search, as targets, in order. */
async function loadAllTargets(search: string): Promise<string[]> {
  const out: string[] = []
  const seen = new Set<string>()
  // Stops at the scan's direct-target limit: more could never be sent.
  for (let page = 1; page <= Math.ceil(MAX_DIRECT_TARGETS / SCOPE_PAGE_SIZE) + 1; page++) {
    const res = await get<{ data?: ApiScopeTarget[]; total?: number }>(pageURL(page, search))
    const rows = res?.data ?? []
    for (const e of rows) {
      const target = scopeEntryTarget(e)
      if (!target || seen.has(targetKey(target))) continue
      seen.add(targetKey(target))
      out.push(target)
    }
    if (rows.length < SCOPE_PAGE_SIZE || page * SCOPE_PAGE_SIZE >= (res?.total ?? 0)) break
  }
  return out
}

export function ScopeSource({ present, onChange }: ScopeSourceProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const allowed = can(Permission.ScopeRead)
  const [search, setSearch] = useState('')
  const term = useSearchQuery(search).term
  const [adding, setAdding] = useState(false)
  const { data, isLoading } = useScopeTargetsApi(
    allowed
      ? {
          target_type: TYPES,
          status: 'active',
          search: term || undefined,
          per_page: SCOPE_PAGE_SIZE,
          sort_by: 'pattern',
          sort_order: 'asc',
        }
      : undefined,
    { isPaused: () => !allowed }
  )
  const entries = useMemo(() => (allowed ? (data?.data ?? []) : []), [allowed, data])
  const total = data?.total ?? entries.length

  const rows = entries.map((e) => {
    const target = scopeEntryTarget(e)
    const pattern = e.pattern ?? ''
    const type = e.target_type ?? ''
    const days = expiresInDays(e.expires_at)
    const soon = days !== null && days <= SCOPE_EXPIRY_WARN_DAYS
    return {
      id: e.id ?? pattern,
      label: target ?? pattern,
      mono: true,
      picked: target ? present.has(targetKey(target)) : false,
      disabled: !target,
      description: !target ? (
        t('scans.scopeSource.notATarget')
      ) : soon ? (
        <span className="inline-flex items-center gap-1 text-warning">
          <AlertTriangle className="h-3 w-3" aria-hidden />
          {t('scans.scopeSource.expiresIn', undefined, { count: days })}
        </span>
      ) : target !== pattern ? (
        t('scans.scopeSource.fromEntry', undefined, { pattern })
      ) : undefined,
      trailing: (
        <Badge variant="outline" className="shrink-0 text-xs">
          {t(`scans.scopeSource.type.${type}`, type)}
        </Badge>
      ),
    }
  })

  const addAll = async () => {
    setAdding(true)
    try {
      const all = await loadAllTargets(term)
      const fresh = all.filter((x) => !present.has(targetKey(x)))
      const room = Math.max(0, MAX_DIRECT_TARGETS - present.size)
      onChange(fresh.slice(0, room), true)
      if (fresh.length > room) {
        toast.warning(
          t('scans.assets.selectedFirst', undefined, {
            max: MAX_DIRECT_TARGETS.toLocaleString(),
            total: (present.size + fresh.length).toLocaleString(),
          })
        )
      }
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.scopeSource.loadFailed')))
    } finally {
      setAdding(false)
    }
  }

  if (!allowed) {
    return <p className="text-sm text-muted-foreground">{t('scans.scopeSource.noAccess')}</p>
  }

  return (
    <PickerList
      search={search}
      onSearch={setSearch}
      searchPlaceholder={t('scans.scopeSource.searchPlaceholder')}
      searchLabel={t('scans.scopeSource.search')}
      listLabel={t('scans.scopeSource.list')}
      loading={isLoading}
      emptyText={
        term
          ? t('scans.scopeSource.noMatch', undefined, { query: term })
          : t('scans.scopeSource.none')
      }
      rows={rows}
      onToggle={(row, picked) => {
        const e = entries.find((x) => (x.id ?? x.pattern) === row.id)
        const target = e ? scopeEntryTarget(e) : null
        if (target) onChange([target], picked)
      }}
      actions={
        total > 0 && (
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">
              {t('scans.scopeSource.count', undefined, { count: total })}
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-8 max-sm:min-h-11"
              onClick={() => void addAll()}
              disabled={adding}
              data-testid="scope-add-all"
            >
              {adding && <Loader2 className="me-1.5 h-3.5 w-3.5 animate-spin" aria-hidden />}
              {term ? t('scans.scopeSource.addAllMatching') : t('scans.scopeSource.addAll')}
            </Button>
          </div>
        )
      }
      footer={
        <p className="text-xs text-muted-foreground">
          {total > entries.length
            ? `${t('scans.groups.showing', undefined, { shown: entries.length, total })} `
            : ''}
          {t('scans.scopeSource.footer')}
        </p>
      }
    />
  )
}
