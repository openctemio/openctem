'use client'

/**
 * Dynamic targets (RFC-068): shown when the scan has a `*.x` target or a
 * CIDR. Says that they are resolved again at the start of every run, previews
 * what the inventory holds for each one now, and sets how a run resolves
 * them (CIDR: sweep or known hosts; freshness).
 */

import { useMemo } from 'react'
import { RefreshCw } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { ScanTargetOptions } from '@/lib/api/scan-types'
import { formatRelative } from '@/lib/format-date'
import {
  hasCidrTarget,
  MAX_SELECTOR_TARGETS,
  SEEN_WITHIN_CHOICES,
  selectorsOf,
} from '../../lib/dynamic-targets'
import { useSelectorPreview } from '../../hooks/use-selector-preview'

interface DynamicTargetsPanelProps {
  /** The targets as they will be stored (after the coverage level). */
  targets: string[]
  options: ScanTargetOptions | undefined
  onChange: (options: ScanTargetOptions) => void
  /** A workflow: discovery steps add names during the run. */
  workflow?: boolean
}

export function DynamicTargetsPanel({
  targets,
  options,
  onChange,
  workflow,
}: DynamicTargetsPanelProps) {
  const { t } = useTranslation()
  const selectors = useMemo(() => selectorsOf(targets, options), [targets, options])
  const cidr = useMemo(() => hasCidrTarget(targets), [targets])
  const { previews, isLoading, enabled } = useSelectorPreview(selectors, options)
  if (selectors.length === 0 && !cidr) return null

  const set = (patch: Partial<ScanTargetOptions>) => onChange({ ...(options ?? {}), ...patch })
  const seenWithin = options?.seen_within_days ?? 0
  // A window set through the API that the list does not offer stays visible.
  const windows = (SEEN_WITHIN_CHOICES as readonly number[]).includes(seenWithin)
    ? SEEN_WITHIN_CHOICES
    : [...SEEN_WITHIN_CHOICES, seenWithin].sort((a, b) => a - b)

  return (
    <fieldset className="space-y-3 rounded-lg border p-3" data-testid="dynamic-targets">
      <legend className="flex items-center gap-1.5 px-1 text-sm font-medium">
        <RefreshCw className="h-3.5 w-3.5" aria-hidden />
        {t('scans.dynamic.title')}
      </legend>
      <p className="text-xs text-muted-foreground">
        {t('scans.dynamic.intro')}
        {workflow && ` ${t('scans.dynamic.workflowNote')}`} {t('scans.dynamic.scopeNote')}
      </p>

      {selectors.length > 0 && (
        <ul className="space-y-2" aria-live="polite">
          {selectors.map((sel) => {
            const p = previews.find(
              (x) => x.selector.kind === sel.kind && x.selector.value === sel.value
            )
            return (
              <li key={`${sel.kind}:${sel.value}`} className="rounded-md bg-muted/40 px-3 py-2">
                <p className="break-all font-mono text-sm">{sel.target}</p>
                <p className="text-xs text-muted-foreground">
                  {!enabled
                    ? t('scans.dynamic.needAssetRead')
                    : isLoading && !p
                      ? t('scans.targets.lookingUp')
                      : !p
                        ? t('scans.dynamic.notLookedUp')
                        : sel.kind === 'wildcard'
                          ? p.total === 0
                            ? t('scans.dynamic.wildcardEmpty', undefined, { value: sel.value })
                            : t(
                                p.total === 1
                                  ? 'scans.dynamic.wildcardOne'
                                  : 'scans.dynamic.wildcardMany',
                                undefined,
                                {
                                  value: sel.value,
                                  count: p.total.toLocaleString(),
                                  cap:
                                    p.total > MAX_SELECTOR_TARGETS
                                      ? t('scans.dynamic.wildcardCap', undefined, {
                                          max: MAX_SELECTOR_TARGETS.toLocaleString(),
                                        })
                                      : '',
                                }
                              )
                          : p.total === 0
                            ? t('scans.dynamic.cidrEmpty')
                            : p.total === 1
                              ? t('scans.dynamic.cidrOne')
                              : t('scans.dynamic.cidrMany', undefined, {
                                  count: p.total.toLocaleString(),
                                })}
                </p>
                {p && p.recent.length > 0 && (
                  <p className="truncate text-xs text-muted-foreground">
                    {t('scans.dynamic.seenRecently', undefined, {
                      names:
                        p.recent[0].name +
                        (p.recent[0].lastSeen ? ` (${formatRelative(p.recent[0].lastSeen)})` : '') +
                        (p.recent.length > 1
                          ? `, ${p.recent
                              .slice(1)
                              .map((r) => r.name)
                              .join(', ')}`
                          : ''),
                    })}
                  </p>
                )}
              </li>
            )
          })}
        </ul>
      )}

      {cidr && (
        <div className="space-y-1.5">
          <p className="text-sm">{t('scans.dynamic.addressRanges')}</p>
          <RadioGroup
            value={options?.cidr_mode === 'inventory' ? 'inventory' : 'sweep'}
            onValueChange={(v) => set({ cidr_mode: v === 'inventory' ? 'inventory' : undefined })}
            className="gap-1"
          >
            <label className="flex cursor-pointer items-start gap-3 rounded-md p-1.5 hover:bg-muted/50">
              <RadioGroupItem
                value="sweep"
                className="mt-0.5"
                aria-label={t('scans.dynamic.sweep')}
              />
              <span className="min-w-0">
                <span className="block text-sm">{t('scans.dynamic.sweep')}</span>
                <span className="block text-xs text-muted-foreground">
                  {t('scans.dynamic.sweepHint')}
                </span>
              </span>
            </label>
            <label className="flex cursor-pointer items-start gap-3 rounded-md p-1.5 hover:bg-muted/50">
              <RadioGroupItem
                value="inventory"
                className="mt-0.5"
                aria-label={t('scans.dynamic.inventoryOnly')}
              />
              <span className="min-w-0">
                <span className="block text-sm">{t('scans.dynamic.inventoryOnly')}</span>
                <span className="block text-xs text-muted-foreground">
                  {t('scans.dynamic.inventoryOnlyHint')}
                </span>
              </span>
            </label>
          </RadioGroup>
        </div>
      )}

      {selectors.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <div className="flex items-center gap-2">
            <Label htmlFor="dyn-seen-within" className="text-sm font-normal">
              {t('scans.dynamic.seenWithin')}
            </Label>
            <Select
              value={String(seenWithin)}
              onValueChange={(v) => set({ seen_within_days: Number(v) || undefined })}
            >
              <SelectTrigger id="dyn-seen-within" className="h-8 w-28">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {windows.map((d) => (
                  <SelectItem key={d} value={String(d)}>
                    {d === 0
                      ? t('scans.dynamic.anyTime')
                      : t('scans.dynamic.days', undefined, { count: d })}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="dyn-include-stale"
              checked={!!options?.include_stale}
              onCheckedChange={(v) => set({ include_stale: v === true || undefined })}
            />
            <Label htmlFor="dyn-include-stale" className="text-sm font-normal">
              {t('scans.dynamic.includeStale')}
            </Label>
          </div>
        </div>
      )}
    </fieldset>
  )
}
