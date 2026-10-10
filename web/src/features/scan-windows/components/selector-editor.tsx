'use client'

/**
 * Which targets a policy governs. Every filled dimension must match; any
 * value of a dimension matches it. Empty: every target of the organization.
 * Lists the caller cannot read are not offered; ids already in the selector
 * that the caller cannot read stay, shown as hidden.
 */

import { STORED_ASSET_TYPES } from '@/features/asset-types/registry.generated'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { MultiSelect } from '@/features/shared/components/multi-select'
import { Label } from '@/components/ui/label'
import { TagInput } from '@/components/ui/tag-input'
import { useTranslation } from '@/context/i18n-provider'
import { ASSET_CRITICALITY_LEVELS, CRITICALITY_LABELS } from '@/lib/criticality'

import type { SelectorOptions } from '../api/use-selector-options'
import { isEmptySelector, type IdDimension } from '../lib/selector'
import type { ScanWindowSelector } from '../types'

interface SelectorEditorProps {
  value: ScanWindowSelector
  onChange: (value: ScanWindowSelector) => void
  sources: SelectorOptions
  disabled?: boolean
}

export function SelectorEditor({ value, onChange, sources, disabled }: SelectorEditorProps) {
  const { t } = useTranslation()
  const set = (k: keyof ScanWindowSelector, v: string[]) => onChange({ ...value, [k]: v })
  const common = {
    disabled,
    searchPlaceholder: t('scanWindows.selector.search', 'Search…'),
    emptyText: t('scanWindows.selector.none', 'Nothing found.'),
    placeholder: t('scanWindows.selector.any', 'Any'),
    selectedLabel: (n: number) => t('scanWindows.selector.selected', '{n} selected', { n }),
    removeLabel: (l: string) => t('scanWindows.selector.remove', 'Remove {label}', { label: l }),
    unknownLabel: () => t('scanWindows.selector.hiddenOne', 'Hidden item'),
  }
  const idField = (dim: IdDimension, label: string) => {
    if (!sources.canRead[dim] && (value[dim]?.length ?? 0) === 0) return null
    const id = `selector-${dim}`
    return (
      <div className="space-y-1.5">
        <Label htmlFor={id}>{label}</Label>
        <MultiSelect
          id={id}
          options={sources.options[dim]}
          value={value[dim] ?? []}
          onChange={(v) => set(dim, v)}
          loading={sources.loading}
          {...common}
        />
      </div>
    )
  }

  return (
    <fieldset className="space-y-3" disabled={disabled}>
      <legend className="text-sm font-medium">{t('scanWindows.form.targets', 'Targets')}</legend>
      <p className="text-xs text-muted-foreground">
        {isEmptySelector(value)
          ? t(
              'scanWindows.form.targetsEvery',
              'No filter: the policy governs every target of the organization.'
            )
          : t(
              'scanWindows.form.targetsHint',
              'A target must match every filled field; any value of a field matches it.'
            )}
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5 sm:col-span-2">
          <Label htmlFor="selector-tags">{t('scanWindows.selector.tags', 'Tags')}</Label>
          <TagInput
            id="selector-tags"
            value={value.tags ?? []}
            onChange={(v) => set('tags', v)}
            maxTags={50}
            disabled={disabled}
            placeholder={t('scanWindows.selector.tagsPlaceholder', 'Type a tag and press Enter')}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="selector-asset_types">
            {t('scanWindows.selector.assetTypes', 'Asset types')}
          </Label>
          <MultiSelect
            id="selector-asset_types"
            options={STORED_ASSET_TYPES.map((v) => ({ value: v, label: getAssetTypeLabel(v) }))}
            value={value.asset_types ?? []}
            onChange={(v) => set('asset_types', v)}
            {...common}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="selector-criticalities">
            {t('scanWindows.selector.criticality', 'Criticality')}
          </Label>
          <MultiSelect
            id="selector-criticalities"
            options={ASSET_CRITICALITY_LEVELS.map((c) => ({
              value: c,
              label: t(`criticality.${c}`, CRITICALITY_LABELS[c]),
            }))}
            value={value.criticalities ?? []}
            onChange={(v) => set('criticalities', v)}
            {...common}
          />
        </div>
        {idField('asset_group_ids', t('scanWindows.selector.groups', 'Groups'))}
        {idField('business_unit_ids', t('scanWindows.selector.units', 'Business units'))}
        {idField('scan_zone_ids', t('scanWindows.selector.zones', 'Zones'))}
        {idField('scope_target_ids', t('scanWindows.selector.scope', 'Scope entries'))}
        {idField('program_ids', t('scanWindows.selector.programs', 'Programs'))}
      </div>
    </fieldset>
  )
}
