/**
 * Targets Step
 *
 * Laid out in the order a person works: what you type, what happens, how to
 * fix it, then options. One field holds the selection as chips (type or
 * paste to add; assets and asset groups come from a picker sheet); under it
 * one readiness line and the refused targets grouped by reason with the
 * server's ranked remedies (the same component as the Review step); the
 * coverage level and how dynamic targets resolve sit in a collapsed
 * disclosure with a one-line summary. Desktop: two columns, the result
 * column sticky. Research: research/85-new-scan.md.
 */

'use client'

import { useEffect, useEffectEvent, useId, useMemo, useState } from 'react'
import { ChevronDown, FolderOpen, Plus, Target } from 'lucide-react'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { useTranslation } from '@/context/i18n-provider'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { cn } from '@/lib/utils'
import type { NewScanFormData } from '../../types'
import { COVERAGE_LEVELS, type CoverageLevel } from '../../lib/coverage-expansion'
import { useCoverageExpansion } from '../../hooks/use-coverage-expansion'
import { parsePastedTargets } from '../../lib/target-format'
import { MAX_DIRECT_TARGETS } from '../../lib/scan-form'
import { hasCidrTarget, hasDynamicTargets, isWildcardTarget } from '../../lib/dynamic-targets'
import { DynamicTargetsPanel } from './dynamic-targets-panel'
import { AssetSource, type PickedAsset } from '../target-picker/asset-source'
import { GroupSource } from '../target-picker/group-source'
import { canFindLiveHosts } from '../../lib/liveness'
import { intensityForTier, type ProbeTier } from '../../lib/scan-intensity'
import { lowerIntensityAllowed, targetOptionsSummary } from '../../lib/targets-step'
import { useTargetsCheck } from '../../hooks/use-targets-check'
import { useScanWorkflow } from '@/lib/api/scan-workflow-hooks'
import { TargetChipsField, type TargetChip } from './target-chips-field'
import { ReadinessLine, RefusalGroups } from './refusal-groups'

const EXAMPLES = ['example.com', '*.example.com', '203.0.113.0/24', 'https://app.example.com']

interface TargetsStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
  /** Offer the coverage level (new scans; an edit keeps the stored targets). */
  showCoverage?: boolean
  /** An edit of a saved scan: its CIDR mode is kept unless a person switches it. */
  savedScan?: boolean
}

type PickerSource = 'assets' | 'groups'

export function TargetsStep({
  data,
  onChange,
  showCoverage = true,
  savedScan = false,
}: TargetsStepProps) {
  const { t } = useTranslation()
  const ids = useId()
  const fieldId = `${ids}-targets`
  const { data: chosenWorkflow } = useScanWorkflow(
    data.mode === 'workflow' && data.workflowId ? data.workflowId : null,
    { revalidateOnFocus: false }
  )
  const livenessAvailable = canFindLiveHosts(data.mode, chosenWorkflow) === true
  const targets = data.targets
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerSource, setPickerSource] = useState<PickerSource>(() =>
    targets.assetGroupIds.length > 0 && targets.assetIds.length === 0 ? 'groups' : 'assets'
  )
  const [optionsOpen, setOptionsOpen] = useState(false)
  const groupNames = useMemo(() => targets.assetGroupNames ?? {}, [targets.assetGroupNames])
  const pickedGroups = useMemo(
    () =>
      Object.fromEntries(
        targets.assetGroupIds.map((id) => [
          id,
          groupNames[id] ?? t('scans.targets.assetGroupFallback'),
        ])
      ),
    [targets.assetGroupIds, groupNames, t]
  )
  const pickedAssets = useMemo(
    () =>
      Object.fromEntries(
        targets.assetIds.map((id) => [id, targets.assetNames[id] ?? id.slice(0, 8)])
      ),
    [targets.assetIds, targets.assetNames]
  )
  const pasted = useMemo(() => parsePastedTargets(targets.customTargets), [targets.customTargets])

  const setAssets = (assets: PickedAsset[], picked: boolean) => {
    const names = { ...targets.assetNames }
    const set = new Set(targets.assetIds)
    for (const a of assets) {
      if (picked) {
        set.add(a.id)
        names[a.id] = a.name
      } else {
        set.delete(a.id)
        delete names[a.id]
      }
    }
    onChange({ targets: { ...targets, assetIds: [...set], assetNames: names } })
  }
  const toggleGroup = (group: { id: string; name: string }, picked: boolean) => {
    const names = { ...groupNames }
    const set = new Set(targets.assetGroupIds)
    if (picked) {
      set.add(group.id)
      names[group.id] = group.name
    } else {
      set.delete(group.id)
      delete names[group.id]
    }
    onChange({ targets: { ...targets, assetGroupIds: [...set], assetGroupNames: names } })
  }
  const setTyped = (lines: string[]) => onChange({ targets: { ...targets, customTargets: lines } })
  const addTyped = (added: string[]) => {
    const seen = new Set(targets.customTargets.map((l) => l.trim().toLowerCase()))
    const next = [...targets.customTargets]
    for (const a of added) {
      const k = a.trim().toLowerCase()
      if (!k || seen.has(k)) continue
      seen.add(k)
      next.push(a.trim())
    }
    setTyped(next)
  }
  const removeTyped = (line: string) =>
    setTyped(targets.customTargets.filter((l) => l.trim().toLowerCase() !== line.toLowerCase()))
  // Remove targets the scope check refused: typed lines, and picked assets by name.
  const removeTargets = (names: string[]) => {
    const drop = new Set(names.map((n) => n.trim().toLowerCase()))
    const keepAssets = targets.assetIds.filter(
      (id) => !drop.has((targets.assetNames[id] ?? '').toLowerCase())
    )
    const names2 = Object.fromEntries(
      Object.entries(targets.assetNames).filter(([id]) => keepAssets.includes(id))
    )
    onChange({
      targets: {
        ...targets,
        customTargets: targets.customTargets.filter((l) => !drop.has(l.trim().toLowerCase())),
        assetIds: keepAssets,
        assetNames: names2,
      },
    })
  }

  // Typed and picked names: what the coverage level expands.
  const typedTargets = useMemo(
    () => [
      ...targets.assetIds.map((id) => targets.assetNames[id]).filter(Boolean),
      ...pasted.targets,
    ],
    [targets.assetIds, targets.assetNames, pasted.targets]
  )
  const coverage: CoverageLevel = targets.coverage ?? 'host'
  const expansion = useCoverageExpansion(typedTargets, coverage)
  const expandedKey = expansion.added.join('\n')
  const storedKey = (targets.expandedTargets ?? []).join('\n')
  // Store the expansion in the form (sent on submit) when it changes; the
  // latest form is read as an effect event, not a dependency.
  const syncExpansion = useEffectEvent((key: string) => {
    if (key !== storedKey) {
      onChange({ targets: { ...targets, expandedTargets: expansion.added } })
    }
  })
  useEffect(() => {
    syncExpansion(expandedKey)
  }, [expandedKey])

  const rootsLabel = expansion.roots.map((r) => `*.${r}`).join(', ')
  const { check, readiness, sent, sensorPreference } = useTargetsCheck(data)
  const results = check.results ?? []
  const refusedCount = results.filter((r) => !r.allowed).length
  const readyCount = results.length - refusedCount
  const over = sent.length > MAX_DIRECT_TARGETS
  const empty = sent.length === 0 && targets.assetGroupIds.length === 0

  const chips: TargetChip[] = [
    ...targets.assetGroupIds.map((id) => ({
      key: `g:${id}`,
      label: pickedGroups[id],
      kind: 'group' as const,
      onRemove: () => toggleGroup({ id, name: pickedGroups[id] }, false),
    })),
    ...targets.assetIds.map((id) => ({
      key: `a:${id}`,
      label: pickedAssets[id],
      kind: 'asset' as const,
      onRemove: () => setAssets([{ id, name: pickedAssets[id] }], false),
    })),
    ...pasted.targets.map((target) => ({
      key: `t:${target}`,
      label: target,
      kind: 'typed' as const,
      onRemove: () => removeTyped(target),
    })),
    ...pasted.invalid.map((bad, i) => ({
      key: `i:${i}:${bad.input}`,
      label: bad.input,
      kind: 'invalid' as const,
      title: bad.reasonKey ? t(bad.reasonKey, bad.reason) : bad.reason,
      onRemove: () => removeTyped(bad.input),
    })),
    // The *.domain targets the coverage level made of typed or picked
    // domains, and the addresses of `subdomains_ips`.
    ...sent
      .filter((x) => isWildcardTarget(x) && !pasted.targets.includes(x))
      .map((x) => ({ key: `w:${x}`, label: x, kind: 'expanded' as const })),
    ...(coverage === 'subdomains_ips' ? expansion.added : []).map((x) => ({
      key: `e:${x}`,
      label: x,
      kind: 'expanded' as const,
    })),
  ]
  const lastTyped = targets.customTargets.at(-1)

  const offerCoverage = showCoverage && typedTargets.length > 0
  const offerDynamic = hasDynamicTargets(sent, targets.targetOptions) || hasCidrTarget(sent)
  const optionsSummary = targetOptionsSummary(t, {
    coverage: offerCoverage ? coverage : undefined,
    targets: sent,
    options: targets.targetOptions,
  })

  const canLower = (tier: ProbeTier) => lowerIntensityAllowed(data, chosenWorkflow?.steps, tier)

  return (
    <div className="grid min-w-0 gap-6 p-4 sm:p-6 lg:grid-cols-2 lg:grid-rows-[auto_1fr] lg:gap-8">
      {/* 1. What you type */}
      <section className="min-w-0 space-y-2 lg:col-start-1" aria-labelledby={`${fieldId}-label`}>
        <label id={`${fieldId}-label`} htmlFor={fieldId} className="text-sm font-medium">
          {t('scans.targetsStep.label')}
        </label>
        <TargetChipsField
          id={fieldId}
          chips={chips}
          onAdd={addTyped}
          onRemoveLast={lastTyped ? () => removeTyped(lastTyped) : undefined}
          invalid={pasted.invalid.length > 0}
          describedBy={`${fieldId}-help`}
        />
        <p id={`${fieldId}-help`} className="text-xs text-muted-foreground">
          {t('scans.targetsStep.help')}
        </p>
        {pasted.invalid.length > 0 && (
          <p role="alert" className="text-xs text-destructive">
            {t(
              pasted.invalid.length === 1
                ? 'scans.summary.invalidOne'
                : 'scans.summary.invalidMany',
              undefined,
              { count: pasted.invalid.length }
            )}
          </p>
        )}
        {over && (
          <p role="alert" className="text-xs text-destructive">
            {t('scans.summary.tooMany', undefined, {
              count: sent.length.toLocaleString(),
              max: MAX_DIRECT_TARGETS.toLocaleString(),
            })}
          </p>
        )}
        {empty && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted-foreground">{t('scans.paste.examples')}</span>
            {EXAMPLES.map((example) => (
              <button
                key={example}
                type="button"
                onClick={() => addTyped([example])}
                className="min-h-8 rounded bg-muted px-2 font-mono text-xs text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground"
              >
                {example}
              </button>
            ))}
          </div>
        )}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="-ms-2 h-9 max-sm:min-h-11"
          onClick={() => setPickerOpen(true)}
        >
          <Plus className="me-1.5 h-4 w-4" aria-hidden />
          {t('scans.targetsStep.fromInventory')}
        </Button>
      </section>

      {/* 2. What happens, 3. how to fix it */}
      <section
        className="min-w-0 space-y-3 lg:sticky lg:top-0 lg:col-start-2 lg:row-span-2 lg:row-start-1 lg:self-start"
        aria-label={t('scans.summary.label')}
        data-testid="targets-result"
      >
        {empty ? (
          <p className="text-sm text-muted-foreground">{t('scans.summary.nothing')}</p>
        ) : (
          <ReadinessLine
            total={sent.length}
            ready={readyCount}
            blocked={refusedCount}
            checking={check.available && check.isLoading && results.length === 0}
            groupCount={targets.assetGroupIds.length}
          />
        )}
        {targets.assetGroupIds.length > 0 && (
          <p className="text-xs text-muted-foreground">{t('scans.summary.groupMembersLater')}</p>
        )}
        {readiness.state === 'partial' && (
          <p className="text-xs text-muted-foreground">
            {t('scans.targetsStep.partial', undefined, {
              count: sent.length - readiness.scannable,
            })}
          </p>
        )}
        {check.error && (
          <p className="text-xs text-muted-foreground">{t('scans.scope.unavailable')}</p>
        )}
        <RefusalGroups
          results={results}
          probeTier={check.tier}
          sensorPreference={sensorPreference}
          onRemove={removeTargets}
          onUseOwnSensors={() => onChange({ sensorPreference: 'tenant' })}
          onLowerIntensity={(tier) => onChange({ intensity: intensityForTier(tier) })}
          canLowerIntensity={canLower}
          onRecheck={() => void check.recheck()}
        />
      </section>

      {/* 4. Options, collapsed */}
      {(offerCoverage || offerDynamic) && (
        <Collapsible
          open={optionsOpen}
          onOpenChange={setOptionsOpen}
          className="min-w-0 lg:col-start-1 lg:self-start"
        >
          <CollapsibleTrigger asChild>
            <button
              type="button"
              className="flex min-h-11 w-full min-w-0 items-start gap-2 text-start lg:border-t lg:pt-3"
            >
              <ChevronDown
                className={cn(
                  'mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-transform',
                  !optionsOpen && '-rotate-90'
                )}
                aria-hidden
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium">{t('scans.targetsStep.options')}</span>
                {optionsSummary && (
                  <span
                    className="block text-xs text-muted-foreground"
                    data-testid="options-summary"
                  >
                    {optionsSummary}
                  </span>
                )}
              </span>
            </button>
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-4 pt-3">
            {offerCoverage && (
              <fieldset className="min-w-0 space-y-2">
                <legend className="text-sm font-medium">{t('scans.targets.coverage')}</legend>
                <RadioGroup
                  value={coverage}
                  onValueChange={(v) =>
                    onChange({ targets: { ...targets, coverage: v as CoverageLevel } })
                  }
                  className="gap-1"
                >
                  {COVERAGE_LEVELS.map((lvl) => (
                    <label
                      key={lvl.id}
                      className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-2 hover:bg-muted/50"
                    >
                      <RadioGroupItem
                        value={lvl.id}
                        className="mt-0.5"
                        aria-label={t(`scans.coverage.${lvl.id}.label`, lvl.label)}
                      />
                      <span className="min-w-0">
                        <span className="block text-sm">
                          {t(`scans.coverage.${lvl.id}.label`, lvl.label)}
                        </span>
                        <span className="block text-xs text-muted-foreground">
                          {t(`scans.coverage.${lvl.id}.hint`, lvl.hint)}
                        </span>
                      </span>
                    </label>
                  ))}
                </RadioGroup>
                {coverage !== 'host' && (
                  <p className="text-xs text-muted-foreground" aria-live="polite">
                    {expansion.roots.length === 0
                      ? t('scans.targets.noDomains')
                      : coverage === 'subdomains'
                        ? t('scans.targets.subdomainsNote', undefined, { roots: rootsLabel })
                        : expansion.isLoading
                          ? t('scans.targets.lookingUp')
                          : expansion.added.length === 0
                            ? t('scans.targets.noRecordedAddresses', undefined, {
                                roots: rootsLabel,
                              })
                            : expansion.added.length === 1
                              ? t('scans.targets.addsOne', undefined, { roots: rootsLabel })
                              : t('scans.targets.addsMany', undefined, {
                                  roots: rootsLabel,
                                  count: expansion.added.length,
                                })}
                  </p>
                )}
              </fieldset>
            )}
            <DynamicTargetsPanel
              targets={sent}
              options={targets.targetOptions}
              onChange={(targetOptions) => onChange({ targets: { ...targets, targetOptions } })}
              workflow={data.mode === 'workflow'}
              savedScan={savedScan}
              livenessAvailable={livenessAvailable}
            />
          </CollapsibleContent>
        </Collapsible>
      )}

      <Sheet open={pickerOpen} onOpenChange={setPickerOpen}>
        <SheetContent side="right" className="sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>{t('scans.targetsStep.pickerTitle')}</SheetTitle>
            <SheetDescription>{t('scans.targetsStep.pickerDescription')}</SheetDescription>
          </SheetHeader>
          <SheetBody>
            <Tabs value={pickerSource} onValueChange={(v) => setPickerSource(v as PickerSource)}>
              <TabsList className="w-full">
                <TabsTrigger value="assets" className="flex-1">
                  <Target className="h-4 w-4" aria-hidden />
                  {t('scans.targets.tabAssets')}
                  <TabsCount value={targets.assetIds.length || null} />
                </TabsTrigger>
                <TabsTrigger value="groups" className="flex-1">
                  <FolderOpen className="h-4 w-4" aria-hidden />
                  {t('scans.targets.tabGroups')}
                  <TabsCount value={targets.assetGroupIds.length || null} />
                </TabsTrigger>
              </TabsList>
              <TabsContent value="assets" className="pt-3">
                <AssetSource selected={pickedAssets} onChange={setAssets} />
              </TabsContent>
              <TabsContent value="groups" className="pt-3">
                <GroupSource selected={pickedGroups} onToggle={toggleGroup} />
              </TabsContent>
            </Tabs>
          </SheetBody>
          <SheetFooter>
            <Button type="button" onClick={() => setPickerOpen(false)}>
              {t('scans.targetsStep.pickerDone')}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  )
}
