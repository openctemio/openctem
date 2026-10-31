'use client'

/**
 * The Access section of a team (api RFC-127): which presets members get and
 * which assets they see. One controlled component for the create form and the
 * team's Access tab. The API is the authority: it refuses an all-assets or
 * elevated change from anyone but an owner; this only keeps the choices honest.
 */

import { ShieldAlert } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import type { TeamPresetTemplate, TeamScopeMode } from '../types'

export interface TeamAccessValue {
  presets: string[]
  scopeMode: TeamScopeMode
}

export const EMPTY_TEAM_ACCESS: TeamAccessValue = { presets: [], scopeMode: 'specific' }

/** Whether the choices make a team elevated: all assets, or a preset that sees all assets. */
export function isElevatedChoice(value: TeamAccessValue, templates: TeamPresetTemplate[]): boolean {
  return (
    value.scopeMode === 'all_assets' ||
    value.presets.some((id) => templates.find((tpl) => tpl.id === id)?.has_full_data_access)
  )
}

export function ElevatedBadge() {
  const { t } = useTranslation()
  return (
    <Badge
      variant="outline"
      className="gap-1 text-xs"
      title={t(
        'org.teamAccess.elevatedHint',
        'Only an owner changes this team, with a recent sign-in. Adding people needs the members permission.'
      )}
    >
      <ShieldAlert className="h-3 w-3" />
      {t('org.teamAccess.elevated', 'Elevated access')}
    </Badge>
  )
}

export function TeamAccessFields({
  idPrefix,
  templates,
  loading,
  value,
  onChange,
  canSetAllAssets,
  disabled,
  blockFullData,
}: {
  idPrefix: string
  templates: TeamPresetTemplate[]
  loading?: boolean
  value: TeamAccessValue
  onChange: (next: TeamAccessValue) => void
  /** Only an owner chooses All assets. */
  canSetAllAssets: boolean
  disabled?: boolean
  /**
   * The team has members outside the organization: the choices that give
   * full data access (a preset that sees all assets, All assets) are off,
   * unless already chosen, and carry this reason.
   */
  blockFullData?: string
}) {
  const { t } = useTranslation()
  const elevated = isElevatedChoice(value, templates)

  function toggle(id: string, on: boolean) {
    const presets = on ? [...value.presets, id] : value.presets.filter((p) => p !== id)
    onChange({ ...value, presets })
  }

  return (
    <div className="space-y-5" data-testid="team-access-fields">
      <fieldset className="space-y-2" disabled={disabled}>
        <legend className="text-sm font-medium">
          {t('org.teamAccess.canDo', 'What members can do')}
        </legend>
        <p className="text-xs text-muted-foreground">
          {t(
            'org.teamAccess.canDoHint',
            'Pick the kinds of work this team does. Members get everything the presets allow as soon as they join, and lose it when they leave. Choose none to only control which assets they see.'
          )}
        </p>
        {loading ? (
          <div className="space-y-2" aria-hidden>
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : (
          <ul className="space-y-1.5">
            {templates.map((tpl) => {
              const id = `${idPrefix}-preset-${tpl.id}`
              return (
                <li key={tpl.id} className="flex items-start gap-3 rounded-lg border p-3">
                  <Checkbox
                    id={id}
                    checked={value.presets.includes(tpl.id)}
                    onCheckedChange={(c) => toggle(tpl.id, c === true)}
                    disabled={
                      disabled ||
                      (!!blockFullData &&
                        tpl.has_full_data_access &&
                        !value.presets.includes(tpl.id))
                    }
                    aria-describedby={
                      blockFullData && tpl.has_full_data_access ? `${id}-blocked` : undefined
                    }
                    className="mt-0.5"
                  />
                  <div className="min-w-0 flex-1 space-y-0.5">
                    <Label htmlFor={id} className="flex flex-wrap items-center gap-2 font-medium">
                      {tpl.name}
                      {tpl.has_full_data_access && (
                        <Badge variant="outline" className="text-xs">
                          {t('org.teamAccess.seesAll', 'Sees all assets')}
                        </Badge>
                      )}
                    </Label>
                    <p className="text-xs text-muted-foreground">{tpl.description}</p>
                    {blockFullData && tpl.has_full_data_access && (
                      <p id={`${id}-blocked`} className="text-xs text-muted-foreground">
                        {blockFullData}
                      </p>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
        )}
      </fieldset>

      <fieldset className="space-y-2" disabled={disabled}>
        <legend className="text-sm font-medium">
          {t('org.teamAccess.canSee', 'What members can see')}
        </legend>
        <RadioGroup
          value={value.scopeMode}
          onValueChange={(v) => onChange({ ...value, scopeMode: v as TeamScopeMode })}
          disabled={disabled}
          aria-label={t('org.teamAccess.canSee', 'What members can see')}
        >
          <div className="flex items-start gap-3 rounded-lg border p-3">
            <RadioGroupItem value="specific" id={`${idPrefix}-scope-specific`} className="mt-0.5" />
            <div className="space-y-0.5">
              <Label htmlFor={`${idPrefix}-scope-specific`} className="font-medium">
                {t('org.teamAccess.specific', 'Specific assets')}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t(
                  'org.teamAccess.specificHint',
                  'Only the assets of this team: its scope rules and the assets assigned to it.'
                )}
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3 rounded-lg border p-3">
            <RadioGroupItem
              value="all_assets"
              id={`${idPrefix}-scope-all`}
              disabled={(!canSetAllAssets || !!blockFullData) && value.scopeMode !== 'all_assets'}
              className="mt-0.5"
            />
            <div className="space-y-0.5">
              <Label
                htmlFor={`${idPrefix}-scope-all`}
                className="flex items-center gap-2 font-medium"
              >
                {t('org.teamAccess.allAssets', 'All assets')}
                <ElevatedBadge />
              </Label>
              <p className="text-xs text-muted-foreground">
                {canSetAllAssets
                  ? t(
                      'org.teamAccess.allAssetsHint',
                      'Every asset in the organization. People outside your organization and service accounts cannot join such a team.'
                    )
                  : t(
                      'org.teamAccess.allAssetsOwnerOnly',
                      'Every asset in the organization. Only an owner can choose this.'
                    )}
              </p>
            </div>
          </div>
        </RadioGroup>
      </fieldset>

      {elevated && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground" role="note">
          <ElevatedBadge />
          <span>
            {canSetAllAssets
              ? t(
                  'org.teamAccess.elevatedNote',
                  'This team will have elevated access. You will be asked to sign in again to save it.'
                )
              : t(
                  'org.teamAccess.elevatedOwnerNote',
                  'This team would have elevated access, which only an owner can set.'
                )}
          </span>
        </div>
      )}
    </div>
  )
}
