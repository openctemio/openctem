'use client'

/**
 * The settings of dynamic targets (RFC-068), placed by the Targets step next
 * to the group they apply to: how address ranges are scanned (live hosts
 * first, every address, or only the hosts the inventory holds), what a
 * wildcard or inventory range holds now, and the freshness options of
 * everything resolved again at the start of every run.
 */

import { useState } from 'react'
import { ChevronDown, Sparkles } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { ChoiceGroup } from '@/components/ui/choice-group'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { ScanTargetOptions } from '@/lib/api/scan-types'
import { formatRelative } from '@/lib/format-date'
import { cn } from '@/lib/utils'
import {
  asCidrMode,
  MAX_SELECTOR_TARGETS,
  SEEN_WITHIN_CHOICES,
  type CidrMode,
  type TargetSelector,
} from '../../lib/dynamic-targets'
import type { SelectorPreview } from '../../hooks/use-selector-preview'
import { effectiveCidrMode } from '../../lib/liveness'
import type { Translate } from '../../lib/translate'
import { selectorOptionsSummary } from '../../lib/targets-step'

interface CidrModeChoiceProps {
  options: ScanTargetOptions | undefined
  onChange: (options: ScanTargetOptions) => void
  /** An edit of a saved scan: without a stored mode it sweeps, and keeps it until switched. */
  savedScan?: boolean
  /** The scan can run live hosts first; undefined while its workflow loads. */
  livenessAvailable?: boolean
}

/** How the scan's address ranges are scanned. */
export function CidrModeChoice({
  options,
  onChange,
  savedScan = false,
  livenessAvailable,
}: CidrModeChoiceProps) {
  const { t } = useTranslation()
  const mode = effectiveCidrMode(options?.cidr_mode, savedScan, livenessAvailable)
  const set = (patch: Partial<ScanTargetOptions>) => onChange({ ...(options ?? {}), ...patch })
  const cannotLive = livenessAvailable === false
  return (
    <div className="min-w-0 space-y-2">
      <ChoiceGroup<CidrMode>
        label={t('scans.dynamic.addressRanges')}
        value={mode}
        onValueChange={(v) => set({ cidr_mode: asCidrMode(v) })}
        data-testid="cidr-mode"
        options={[
          {
            value: 'liveness',
            label: t('scans.dynamic.liveness'),
            hint: t('scans.dynamic.livenessHint'),
            // A workflow without Host discovery: the API refuses it.
            disabled: cannotLive && mode !== 'liveness',
            disabledReason: cannotLive ? t('scans.dynamic.livenessNeedsDiscovery') : undefined,
          },
          { value: 'sweep', label: t('scans.dynamic.sweep'), hint: t('scans.dynamic.sweepHint') },
          {
            value: 'inventory',
            label: t('scans.dynamic.inventoryOnly'),
            hint: t('scans.dynamic.inventoryOnlyHint'),
          },
        ]}
      />
      {savedScan && livenessAvailable && mode === 'sweep' && (
        <div
          role="note"
          className="flex flex-wrap items-center gap-2 rounded-md border border-info/40 bg-info/10 px-3 py-2"
          data-testid="liveness-suggestion"
        >
          <Sparkles className="h-3.5 w-3.5 shrink-0 text-info" aria-hidden />
          <span className="min-w-0 flex-1 text-xs">
            <span className="block font-medium">{t('scans.dynamic.livenessSuggestion')}</span>
            <span className="block text-muted-foreground">
              {t('scans.dynamic.livenessSuggestionHint')}
            </span>
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="h-7 max-sm:min-h-11"
            onClick={() => set({ cidr_mode: 'liveness' })}
          >
            {t('scans.dynamic.livenessSwitch')}
          </Button>
        </div>
      )}
      {/* Without a stored mode, say why this one is shown (a new scan's default needs no note). */}
      {!options?.cidr_mode && (savedScan || cannotLive) && (
        <p className="text-xs text-muted-foreground">
          {t(savedScan ? 'scans.dynamic.cidrModeNoticeSaved' : 'scans.dynamic.cidrModeNoticeSweep')}
        </p>
      )}
    </div>
  )
}

/** What a selector holds now, in words. */
export function selectorPreviewText(
  t: Translate,
  sel: TargetSelector,
  p: SelectorPreview | undefined,
  state: { enabled: boolean; isLoading: boolean }
): string {
  if (!state.enabled) return t('scans.dynamic.needAssetRead')
  if (state.isLoading && !p) return t('scans.targets.lookingUp')
  if (!p) return t('scans.dynamic.notLookedUp')
  if (sel.kind === 'wildcard') {
    if (p.total === 0) return t('scans.dynamic.wildcardEmpty', undefined, { value: sel.value })
    return t(
      p.total === 1 ? 'scans.dynamic.wildcardOne' : 'scans.dynamic.wildcardMany',
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
  }
  if (p.total === 0) return t('scans.dynamic.cidrEmpty')
  if (p.total === 1) return t('scans.dynamic.cidrOne')
  return t('scans.dynamic.cidrMany', undefined, { count: p.total.toLocaleString() })
}

/** The names a selector matched recently: one line, the full list as a tooltip. */
export function recentNamesText(
  t: Translate,
  recent: readonly { name: string; lastSeen?: string }[]
): string {
  if (recent.length === 0) return ''
  return t('scans.dynamic.seenRecently', undefined, {
    names:
      recent[0].name +
      (recent[0].lastSeen ? ` (${formatRelative(recent[0].lastSeen)})` : '') +
      (recent.length > 1
        ? `, ${recent
            .slice(1)
            .map((r) => r.name)
            .join(', ')}`
        : ''),
  })
}

interface SelectorOptionsProps {
  options: ScanTargetOptions | undefined
  onChange: (options: ScanTargetOptions) => void
  /** A workflow: discovery steps add names during the run. */
  workflow?: boolean
}

/** Freshness of what is resolved at every run: collapsed, with its summary. */
export function SelectorOptions({ options, onChange, workflow }: SelectorOptionsProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const set = (patch: Partial<ScanTargetOptions>) => onChange({ ...(options ?? {}), ...patch })
  const seenWithin = options?.seen_within_days ?? 0
  // A window set through the API that the list does not offer stays visible.
  const windows = (SEEN_WITHIN_CHOICES as readonly number[]).includes(seenWithin)
    ? SEEN_WITHIN_CHOICES
    : [...SEEN_WITHIN_CHOICES, seenWithin].sort((a, b) => a - b)

  return (
    <Collapsible open={open} onOpenChange={setOpen} data-testid="dynamic-targets">
      <CollapsibleTrigger asChild>
        <button type="button" className="flex min-h-11 w-full min-w-0 items-start gap-2 text-start">
          <ChevronDown
            className={cn(
              'mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-transform',
              !open && '-rotate-90'
            )}
            aria-hidden
          />
          <span className="min-w-0 flex-1">
            <span className="block text-sm font-medium">{t('scans.dynamic.title')}</span>
            <span className="block text-xs text-muted-foreground" data-testid="options-summary">
              {selectorOptionsSummary(t, options)}
            </span>
          </span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent className="space-y-3 ps-6 pt-1">
        <p className="text-xs text-muted-foreground">
          {t('scans.dynamic.intro')}
          {workflow && ` ${t('scans.dynamic.workflowNote')}`} {t('scans.dynamic.scopeNote')}
        </p>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <div className="flex items-center gap-2">
            <Label htmlFor="dyn-seen-within" className="text-sm font-normal">
              {t('scans.dynamic.seenWithin')}
            </Label>
            <Select
              value={String(seenWithin)}
              onValueChange={(v) => set({ seen_within_days: Number(v) || undefined })}
            >
              <SelectTrigger id="dyn-seen-within" className="w-28">
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
        <div className="flex items-start gap-2">
          <Checkbox
            id="dyn-include-unresolved"
            className="mt-0.5"
            checked={!!options?.include_unresolved}
            onCheckedChange={(v) => set({ include_unresolved: v === true || undefined })}
            aria-describedby="dyn-include-unresolved-help"
          />
          <div className="space-y-0.5">
            <Label htmlFor="dyn-include-unresolved" className="text-sm font-normal">
              {t('scans.dynamic.includeUnresolved')}
            </Label>
            <p id="dyn-include-unresolved-help" className="text-xs text-muted-foreground">
              {t('scans.dynamic.includeUnresolvedHelp')}
            </p>
          </div>
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}
