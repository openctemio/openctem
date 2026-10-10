'use client'

import { FacetOption, FacetPanel, FacetSection, FacetToggle } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import type { ComponentFacets, FacetValue } from '../api/types'
import { type ComponentFilterName, listValues, toggleListValue } from '../lib/filters'
import { useRelationshipLabel, useScopeLabel, useSeverityLabel } from './component-cells'

interface ComponentFacetsPanelProps {
  facets: ComponentFacets | undefined
  filters: Record<ComponentFilterName, string>
  activeCount: number
  onChange: (name: ComponentFilterName, value: string) => void
  onClearAll: () => void
}

/** Facets of the filtered set, with the selected values kept visible. */
function withSelected(values: FacetValue[] | undefined, selected: string[]): FacetValue[] {
  const out = [...(values ?? [])]
  for (const s of selected) {
    if (!out.some((v) => v.value === s)) out.push({ value: s, count: 0 })
  }
  return out
}

export function ComponentFacetsPanel({
  facets,
  filters,
  activeCount,
  onChange,
  onClearAll,
}: ComponentFacetsPanelProps) {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  const relationshipLabel = useRelationshipLabel()
  const scopeLabel = useScopeLabel()

  const multi = (
    name: ComponentFilterName,
    title: string,
    values: FacetValue[] | undefined,
    label: (v: string) => string = (v) => v
  ) => {
    const selected = listValues(filters[name])
    const options = withSelected(values, selected)
    if (!options.length) return null
    return (
      <FacetSection title={title} selectedCount={selected.length}>
        {options.map((v) => (
          <FacetOption
            key={v.value}
            label={label(v.value)}
            checked={selected.includes(v.value)}
            onCheckedChange={(on) => onChange(name, toggleListValue(filters[name], v.value, on))}
            adornment={
              <span className="text-xs tabular-nums text-muted-foreground">{v.count}</span>
            }
          />
        ))}
      </FacetSection>
    )
  }

  return (
    <FacetPanel activeCount={activeCount} onClearAll={onClearAll}>
      <FacetSection
        title={t('components.facets.risk', 'Risk')}
        selectedCount={
          [filters.kev, filters.has_fix, filters.has_vulnerabilities].filter(Boolean).length
        }
      >
        <FacetToggle
          label={t('components.facets.vulnerable', 'Has open vulnerabilities')}
          checked={filters.has_vulnerabilities === 'true'}
          onCheckedChange={(on) => onChange('has_vulnerabilities', on ? 'true' : '')}
        />
        <FacetToggle
          label={t('components.facets.kev', 'Known exploited (KEV)')}
          checked={filters.kev === 'true'}
          onCheckedChange={(on) => onChange('kev', on ? 'true' : '')}
        />
        <FacetToggle
          label={t('components.facets.fix', 'Fix available')}
          checked={filters.has_fix === 'true'}
          onCheckedChange={(on) => onChange('has_fix', on ? 'true' : '')}
        />
      </FacetSection>
      {multi(
        'severity',
        t('components.facets.severity', 'Severity'),
        facets?.severity,
        severityLabel
      )}
      {multi('ecosystem', t('components.facets.ecosystem', 'Ecosystem'), facets?.ecosystem)}
      {multi(
        'relationship',
        t('components.facets.relationship', 'Dependency'),
        facets?.relationship,
        relationshipLabel
      )}
      {multi('scope', t('components.facets.scope', 'Scope'), facets?.scope, (v) =>
        String(scopeLabel(v))
      )}
      {multi('license', t('components.facets.license', 'License'), facets?.license)}
    </FacetPanel>
  )
}
