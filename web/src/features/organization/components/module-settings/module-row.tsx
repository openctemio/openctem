'use client'

import { useId, useState } from 'react'
import { ChevronDown, ChevronRight, CornerDownRight, Lock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Marker } from '@/components/ui/marker'
import { Switch } from '@/components/ui/switch'
import { TonePill } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useFormatList } from '@/lib/format-list'
import { cn } from '@/lib/utils'
import { isHiddenReleaseStatus } from '@/lib/permissions'
import type { ModuleHealth, TenantSubModule } from '@/features/organization/api/use-tenant-modules'
import { useModuleText } from './use-module-text'

/** Why a module cannot be switched here, shown in place of the switch action. */
export type ModuleLock =
  | { kind: 'always_on' }
  | { kind: 'not_entitled' }
  | { kind: 'platform' }
  | { kind: 'read_only'; until: string }
  | { kind: 'needs_unavailable'; modules: string[] }
  | { kind: 'coming_soon' }

/** What the pending save does to this module. */
export type ModuleChange =
  | { kind: 'on' }
  | { kind: 'off' }
  | { kind: 'off_with'; because: string[] }
  | { kind: 'on_with'; because: string[] }

export interface ModuleRowProps {
  id: string
  /** Registry name and description from the API: the fallback text. */
  apiName: string
  apiDescription?: string
  beta?: boolean
  /** The state after the pending save (the saved state when nothing changes). */
  enabled: boolean
  change?: ModuleChange
  lock?: ModuleLock
  /** The caller may not change modules: the switch shows the state only. */
  readOnly?: boolean
  busy?: boolean
  /** Non-core modules this one hard-requires, and those that hard-require it. */
  requires?: string[]
  requiredBy?: string[]
  /** Fallback names for module ids (API text). */
  apiNames: Record<string, string>
  health?: ModuleHealth
  healthDetail?: string
  subModules?: TenantSubModule[]
  /** Sub-module id -> state after the pending save. */
  subEnabled?: Record<string, boolean>
  onToggle: (id: string, next: boolean) => void
}

/**
 * One module on Settings > Modules: its name, a plain description, what it
 * needs and what needs it (written out, never in a tooltip), why it is locked
 * when it is, and the switch with its state in words.
 */
export function ModuleRow({
  id,
  apiName,
  apiDescription,
  beta,
  enabled,
  change,
  lock,
  readOnly,
  busy,
  requires = [],
  requiredBy = [],
  apiNames,
  health,
  healthDetail,
  subModules = [],
  subEnabled = {},
  onToggle,
}: ModuleRowProps) {
  const { t, locale } = useTranslation()
  const text = useModuleText()
  const formatList = useFormatList()
  const nameId = useId()
  const detailId = useId()
  const subsId = useId()
  const [subsOpen, setSubsOpen] = useState(false)
  const name = text.name(id, apiName)
  const description = text.description(id, apiDescription)
  const names = (ids: string[]) => formatList(ids.map((m) => text.name(m, apiNames[m])))
  const visibleSubs = subModules.filter((s) => !isHiddenReleaseStatus(s.release_status))

  const lockText = lock ? lockReason(lock) : undefined
  function lockReason(l: ModuleLock): string {
    switch (l.kind) {
      case 'always_on':
        return t('settings.modules.lock.alwaysOn', 'Always on')
      case 'not_entitled':
        return t(
          'settings.modules.lock.notEntitled',
          'Not available for this organization. The administrator of this installation can make it available.'
        )
      case 'platform':
        return t(
          'settings.modules.lock.platform',
          'Turned off for the whole installation by its administrator.'
        )
      case 'read_only':
        return t(
          'settings.modules.lock.readOnly',
          'No longer available for this organization. Its data can be viewed and exported until {date}; changes are turned off.',
          { date: new Date(l.until).toLocaleDateString(locale) }
        )
      case 'needs_unavailable':
        return t(
          'settings.modules.lock.needsUnavailable',
          'Needs {names}, which this organization does not have.',
          { names: names(l.modules) }
        )
      case 'coming_soon':
        return t('settings.modules.lock.comingSoon', 'Coming soon')
    }
  }

  const switchDisabled = !!lock || readOnly || busy
  const stateWord = enabled
    ? t('settings.modules.state.on', 'On')
    : t('settings.modules.state.off', 'Off')

  return (
    <li className={cn('flex gap-4 px-4 py-3', change && 'bg-muted/40')} data-module={id}>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span id={nameId} className="text-sm font-medium">
            {name}
          </span>
          {beta && <Badge variant="outline">{t('settings.modules.beta', 'Beta')}</Badge>}
          {change && <ChangeBadge change={change} names={names} />}
          {enabled && health === 'degraded' && (
            <TonePill
              tone="warning"
              label={t('settings.modules.health.degraded', 'Degraded')}
              state="degraded"
            />
          )}
        </div>
        <div id={detailId} className="mt-0.5 space-y-0.5">
          {description && (
            <p className="text-sm text-muted-foreground text-pretty">{description}</p>
          )}
          {requires.length > 0 && (
            <p className="text-xs text-muted-foreground">
              {t('settings.modules.requiresNames', 'Requires {names}', { names: names(requires) })}
            </p>
          )}
          {requiredBy.length > 0 && (
            <p className="text-xs text-muted-foreground">
              {t('settings.modules.requiredByNames', 'Required by {names}', {
                names: names(requiredBy),
              })}
            </p>
          )}
          {enabled && health === 'degraded' && healthDetail && (
            <p className="text-xs text-muted-foreground">{healthDetail}</p>
          )}
          {lock && lock.kind !== 'always_on' && (
            <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
              <Lock className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
              <span>{lockText}</span>
            </p>
          )}
        </div>
        {visibleSubs.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="-ms-2 mt-1 text-muted-foreground"
            aria-expanded={subsOpen}
            aria-controls={subsId}
            onClick={() => setSubsOpen((o) => !o)}
          >
            {subsOpen ? (
              <ChevronDown className="h-4 w-4" aria-hidden />
            ) : (
              <ChevronRight className="h-4 w-4" aria-hidden />
            )}
            {t('settings.modules.subFeatures', '{on} of {total} parts on', {
              on: visibleSubs.filter((s) => subEnabled[s.id] ?? s.is_enabled).length,
              total: visibleSubs.length,
            })}
          </Button>
        )}
        {visibleSubs.length > 0 && subsOpen && (
          <ul id={subsId} className="mt-1 max-w-md space-y-1">
            {visibleSubs.map((sub) => (
              <SubModuleRow
                key={sub.id}
                sub={sub}
                enabled={subEnabled[sub.id] ?? sub.is_enabled}
                parentEnabled={enabled}
                disabled={readOnly || busy}
                onToggle={onToggle}
              />
            ))}
          </ul>
        )}
      </div>
      <div className="flex shrink-0 items-start gap-2 pt-0.5">
        {lock?.kind === 'always_on' ? (
          <span className="flex items-center gap-1 text-sm text-muted-foreground">
            <Lock className="h-3.5 w-3.5" aria-hidden />
            {lockText}
          </span>
        ) : (
          <>
            <span className="min-w-6 text-end text-sm text-muted-foreground" aria-hidden>
              {stateWord}
            </span>
            <Switch
              checked={enabled}
              onCheckedChange={(next) => onToggle(id, next)}
              disabled={switchDisabled}
              aria-labelledby={nameId}
              aria-describedby={detailId}
            />
          </>
        )}
      </div>
    </li>
  )
}

function ChangeBadge({
  change,
  names,
}: {
  change: ModuleChange
  names: (ids: string[]) => string
}) {
  const { t } = useTranslation()
  const label =
    change.kind === 'on'
      ? t('settings.modules.change.on', 'Turns on')
      : change.kind === 'off'
        ? t('settings.modules.change.off', 'Turns off')
        : change.kind === 'off_with'
          ? t('settings.modules.change.offWith', 'Turns off with {names}', {
              names: names(change.because),
            })
          : t('settings.modules.change.onWith', 'Turns on for {names}', {
              names: names(change.because),
            })
  return <Badge variant="secondary">{label}</Badge>
}

function SubModuleRow({
  sub,
  enabled,
  parentEnabled,
  disabled,
  onToggle,
}: {
  sub: TenantSubModule
  enabled: boolean
  parentEnabled: boolean
  disabled?: boolean
  onToggle: (id: string, next: boolean) => void
}) {
  const { t } = useTranslation()
  const text = useModuleText()
  const nameId = useId()
  const comingSoon = sub.release_status === 'coming_soon'
  const on = !comingSoon && enabled
  return (
    <li className="flex items-center justify-between gap-3">
      <span className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground">
        <CornerDownRight className="h-3.5 w-3.5 shrink-0" aria-hidden />
        <span id={nameId}>{text.name(sub.id, sub.name)}</span>
        {sub.release_status === 'beta' && (
          <Badge variant="outline">{t('settings.modules.beta', 'Beta')}</Badge>
        )}
        {comingSoon && <Marker kind="soon" />}
      </span>
      <Switch
        checked={on}
        onCheckedChange={(next) => onToggle(sub.id, next)}
        disabled={disabled || comingSoon || !parentEnabled}
        aria-labelledby={nameId}
      />
    </li>
  )
}
