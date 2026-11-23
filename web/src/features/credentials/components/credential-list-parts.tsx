'use client'

/**
 * Pieces of the credential leaks list (/credentials): the filter values and
 * their URL form, the filter panel (Add filter, and the phone's Filters
 * sheet), the leak date cell and the phone card. The list follows the shared
 * list pattern (web/docs/ui-style-contract.md, "Lists").
 */

import { Layers } from 'lucide-react'
import { HealthStatus } from '@/components/ui/health-status'
import { useTranslation } from '@/context/i18n-provider'
import { FacetOption, FacetPanel, FacetSection, SeverityBadge } from '@/features/shared'
import { MetaLine } from '@/features/shared/components/text-layout'
import type { Severity } from '@/features/shared/types'
import { formatDate } from '@/lib/app-locale'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { CREDENTIAL_TYPES, type CredentialLeakRow } from '../lib'

type TFn = ReturnType<typeof useTranslation>['t']

/** The list's statuses; each stands for one or more API states. */
export const CREDENTIAL_STATUSES = ['active', 'completed', 'inactive'] as const
export type CredentialStatus = (typeof CREDENTIAL_STATUSES)[number]
export const CREDENTIAL_STATUS_STATES: Record<CredentialStatus, string[]> = {
  active: ['active'],
  completed: ['resolved'],
  inactive: ['accepted', 'false_positive'],
}

/** The API's severities, most severe first (the shared list). */
export const CREDENTIAL_SEVERITIES = SEVERITY_LEVELS

/** A leak dated within this many days is marked "Recent". */
const RECENT_DAYS = 30

/** Values of a comma-separated URL filter, limited to `allowed` when given. */
export function listValues(raw: string, allowed?: readonly string[]): string[] {
  const out = raw
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
  return allowed ? out.filter((v) => allowed.includes(v)) : out
}

/** `raw` with `value` added or removed, comma-separated. */
export function toggleListValue(raw: string, value: string, on: boolean): string {
  const set = new Set(listValues(raw))
  if (on) set.add(value)
  else set.delete(value)
  return [...set].join(',')
}

/** Whole days since `date`. */
export function daysSince(date: string): number {
  return Math.ceil((Date.now() - new Date(date).getTime()) / (1000 * 60 * 60 * 24))
}

/** The translated label of an API credential type; an unknown type shows as returned. */
export function credentialTypeLabel(t: TFn, type: string): string {
  const value = type || 'password'
  return (CREDENTIAL_TYPES as readonly string[]).includes(value)
    ? t(`credentials.type.${value}`, value)
    : value
}

export function credentialSourceLabel(t: TFn, source: string): string {
  return t(`credentials.source.${source}`, source.replace(/_/g, ' '))
}

export function credentialStatusLabel(t: TFn, status: CredentialStatus): string {
  return status === 'active'
    ? t('credentials.status.active', 'Active')
    : status === 'completed'
      ? t('credentials.status.resolved', 'Resolved')
      : t('credentials.status.inactive', 'Inactive')
}

export function credentialSeverityLabel(t: TFn, severity: string): string {
  return t(`credentials.severity.${severity}`, severity)
}

/** API severities are free strings; the shared badge falls back for unknown ones. */
export function asSeverity(value: string | undefined): Severity {
  return (value || 'none') as Severity
}

/** How a leak's status reads: an active leak needs action, a resolved one is done. */
const STATUS_HEALTH = { active: 'warn', completed: 'ok', inactive: 'off' } as const

/** A leak's status in the list's words (Active, Resolved, Inactive). */
export function CredentialStatusCell({ status }: { status: string }) {
  const { t } = useTranslation()
  const known = (CREDENTIAL_STATUSES as readonly string[]).includes(status)
  const value = (known ? status : 'active') as CredentialStatus
  return (
    <HealthStatus
      state={STATUS_HEALTH[value]}
      value={value}
      label={credentialStatusLabel(t, value)}
    />
  )
}

/** The leak date, with "Recent" when it is within the last 30 days. */
export function LeakDate({ date, className }: { date: string; className?: string }) {
  const { t } = useTranslation()
  if (!date) return <span className="text-muted-foreground">—</span>
  const recent = daysSince(date) <= RECENT_DAYS
  return (
    <span className={cn('inline-flex flex-wrap items-baseline gap-x-1.5 tabular-nums', className)}>
      <span className={cn(recent && 'font-medium text-destructive')}>
        {formatDate(new Date(date))}
      </span>
      {recent && (
        <span className="text-meta text-destructive">
          {t('credentials.badge.recent', 'Recent')}
        </span>
      )}
    </span>
  )
}

export type CredentialFilterName = 'status' | 'source' | 'severity'

interface CredentialFacetsPanelProps {
  filters: Record<CredentialFilterName, string>
  sources: string[]
  activeCount: number
  /** Leaks grouped by identity: only the status applies there. */
  identityView: boolean
  onChange: (name: CredentialFilterName, value: string) => void
  onClearAll: () => void
  /** The phone's Filters sheet also holds the grouping. */
  group?: { value: 'none' | 'identity'; onChange: (value: 'none' | 'identity') => void }
}

export function CredentialFacetsPanel({
  filters,
  sources,
  activeCount,
  identityView,
  onChange,
  onClearAll,
  group,
}: CredentialFacetsPanelProps) {
  const { t } = useTranslation()
  const section = (
    name: CredentialFilterName,
    title: string,
    values: readonly string[],
    label: (v: string) => string
  ) => {
    // Status and severity take their fixed values only; a source in the link
    // that the server no longer lists stays removable.
    const selected = listValues(filters[name], name === 'source' ? undefined : values)
    const options = [...values, ...selected.filter((s) => !values.includes(s))]
    if (!options.length) return null
    return (
      <FacetSection title={title} selectedCount={selected.length}>
        {options.map((v) => (
          <FacetOption
            key={v}
            label={label(v)}
            checked={selected.includes(v)}
            onCheckedChange={(on) => onChange(name, toggleListValue(filters[name], v, on))}
          />
        ))}
      </FacetSection>
    )
  }
  return (
    <FacetPanel activeCount={activeCount} onClearAll={onClearAll}>
      {group && (
        <FacetSection title={t('credentials.group.title', 'Group by')}>
          {(['none', 'identity'] as const).map((g) => (
            <FacetOption
              key={g}
              label={
                <span className="inline-flex items-center gap-2">
                  {g === 'identity' && (
                    <Layers className="size-4 text-muted-foreground" aria-hidden />
                  )}
                  {g === 'identity'
                    ? t('credentials.group.identity', 'Identity')
                    : t('credentials.group.none', 'No grouping')}
                </span>
              }
              checked={group.value === g}
              onCheckedChange={(on) => on && group.onChange(g)}
            />
          ))}
        </FacetSection>
      )}
      {section('status', t('credentials.col.status', 'Status'), CREDENTIAL_STATUSES, (v) =>
        credentialStatusLabel(t, v as CredentialStatus)
      )}
      {!identityView &&
        section('severity', t('credentials.col.severity', 'Severity'), CREDENTIAL_SEVERITIES, (v) =>
          credentialSeverityLabel(t, v)
        )}
      {!identityView &&
        section('source', t('credentials.col.source', 'Source'), sources, (v) =>
          credentialSourceLabel(t, v)
        )}
    </FacetPanel>
  )
}

/**
 * A leak on a phone. Fixed slots, plain text, one fact per element:
 *
 *   alice@example.com ............................. High
 *   Password, Data breach
 *   Active   Leaked 1 May 2020   Recent
 *
 * The severity slot is always there; the secret is never on the card (only
 * the sheet shows its mask). A tap on the card opens the leak's sheet.
 */
export function CredentialPhoneCard({
  item,
  onOpen,
}: {
  item: CredentialLeakRow
  onOpen: () => void
}) {
  const { t } = useTranslation()
  const name = toDisplayText(item.name, 200)
  const user = toDisplayText(item.metadata.username, 200)
  const facts = [
    credentialTypeLabel(t, item.metadata.credentialType),
    item.metadata.source ? credentialSourceLabel(t, item.metadata.source) : null,
  ].filter(Boolean)
  const leakDate = item.metadata.leakDate
  const recent = !!leakDate && daysSince(leakDate) <= RECENT_DAYS
  return (
    <div
      data-slot="credential-card"
      className="flex cursor-pointer items-start gap-3 px-3 py-3 hover:bg-muted/50"
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a[href], [role="checkbox"]')) return
        onOpen()
      }}
    >
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 items-center justify-between gap-3">
          <span className="min-w-0 truncate font-medium" title={name}>
            {name || <span className="text-muted-foreground">—</span>}
          </span>
          <SeverityBadge severity={asSeverity(item.metadata.severity)} className="shrink-0" />
        </div>
        <p className="truncate text-meta">
          {facts.join(', ')}
          {user && user !== name && <span className="text-muted-foreground">, {user}</span>}
        </p>
        <MetaLine
          items={[
            <span key="status">{credentialStatusLabel(t, item.status as CredentialStatus)}</span>,
            leakDate ? (
              <span key="leak" className={cn('tabular-nums', recent && 'text-destructive')}>
                {t('credentials.mobile.leaked', 'Leaked {date}', {
                  date: formatDate(new Date(leakDate)),
                })}
              </span>
            ) : null,
            recent ? (
              <span key="recent" className="font-medium text-destructive">
                {t('credentials.badge.recent', 'Recent')}
              </span>
            ) : null,
            !leakDate && item.firstSeen ? (
              <span key="seen" className="tabular-nums">
                {t('credentials.mobile.discovered', 'Discovered {date}', {
                  date: formatDate(new Date(item.firstSeen)),
                })}
              </span>
            ) : null,
          ]}
        />
      </div>
    </div>
  )
}
