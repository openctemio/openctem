/**
 * Targets Step
 *
 * Two columns at desktop width: on the left what you scan (one field of chips
 * to type or paste into, "Paste a list", and the picker sheet with assets,
 * asset groups and the organization's in-scope entries); on the right what
 * the scan will probe, grouped by kind with each target's scope answer and
 * the setting that applies to that kind next to it (the coverage level by
 * the domains, how ranges are scanned by the ranges, the freshness of what a
 * run resolves again under the groups), then the refused targets with the
 * server's ranked remedies. A setting is shown only when what was entered
 * uses it. Phone: one column in the same order. Past a few entries the typed
 * targets move from chips to a searchable list. Research:
 * research/85-new-scan.md, research/418.
 */

'use client'

import { useEffect, useEffectEvent, useId, useMemo, useState } from 'react'
import { ClipboardList, FolderOpen, Plus, ShieldCheck, Target } from 'lucide-react'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { ChoiceGroup } from '@/components/ui/choice-group'
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
import { Permission, usePermissions } from '@/lib/permissions'
import type { NewScanFormData } from '../../types'
import { COVERAGE_LEVELS, type CoverageLevel } from '../../lib/coverage-expansion'
import { useCoverageExpansion } from '../../hooks/use-coverage-expansion'
import {
  parsePastedTargets,
  withoutTargets,
  replaceEntryInLines,
  targetReasonText,
  isRefusedKind,
  TARGET_KIND_LABELS,
  targetKey,
  type ClassifiedTarget,
  type TargetKind,
} from '../../lib/target-format'
import { MAX_DIRECT_TARGETS } from '../../lib/scan-form'
import {
  hasCidrTarget,
  hasDynamicTargets,
  isWildcardTarget,
  selectorsOf,
} from '../../lib/dynamic-targets'
import {
  CidrModeChoice,
  recentNamesText,
  SelectorOptions,
  selectorPreviewText,
} from './dynamic-target-controls'
import { useSelectorPreview } from '../../hooks/use-selector-preview'
import { groupTargets } from '../../lib/target-groups'
import { TargetGroups } from './target-groups'
import { ScopeSource } from '../target-picker/scope-source'
import { AssetSource, type PickedAsset } from '../target-picker/asset-source'
import { GroupSource } from '../target-picker/group-source'
import { canFindLiveHosts } from '../../lib/liveness'
import { intensityForTier, type ProbeTier } from '../../lib/scan-intensity'
import { lowerIntensityAllowed } from '../../lib/targets-step'
import { useTargetsCheck } from '../../hooks/use-targets-check'
import { useRangeHostBits } from '../../hooks/use-range-host-bits'
import { useScanWorkflow } from '@/lib/api/scan-workflow-hooks'
import { TargetChipsField, type TargetChip } from './target-chips-field'
import { ReadinessLine, RefusalGroups } from './refusal-groups'
import { TargetList } from './target-list'
import { InvalidTargetsNote } from './invalid-targets-note'
import { LargeRangeConfirm } from './large-range-confirm'
import { largeRangeSummary } from '../../lib/large-range'
import { BulkTargetsPanel } from './bulk-targets-panel'
import { CoreInfraWarning } from './core-infra-warning'

/** Typed targets shown as chips; past this they move to the list. */
export const CHIP_LIMIT = 20

const EXAMPLES = ['example.com', '*.example.com', '203.0.113.0/24', 'https://app.example.com']

interface TargetsStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
  /** Offer the coverage level (new scans; an edit keeps the stored targets). */
  showCoverage?: boolean
  /** An edit of a saved scan: its CIDR mode is kept unless a person switches it. */
  savedScan?: boolean
}

type PickerSource = 'assets' | 'groups' | 'scope'

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
  // undefined while the workflow loads; the ranges choice shows live hosts
  // first until then, which is what the API saves for a scan that can run it.
  const livenessAvailable = canFindLiveHosts(data.mode, chosenWorkflow)
  const targets = data.targets
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerSource, setPickerSource] = useState<PickerSource>(() =>
    targets.assetGroupIds.length > 0 && targets.assetIds.length === 0 ? 'groups' : 'assets'
  )
  const { can } = usePermissions()
  const canReadScope = can(Permission.ScopeRead)
  const [bulkOpen, setBulkOpen] = useState(false)
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
  // The organization's widest range (a /16 unless it opted in to wider).
  const maxHostBits = useRangeHostBits(canReadScope)
  const pasted = useMemo(
    () => parsePastedTargets(targets.customTargets, { maxHostBits }),
    [targets.customTargets, maxHostBits]
  )

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
    const seen = new Set(pasted.lines.map((l) => targetKey(l.input)))
    const next = [...targets.customTargets]
    for (const a of added) {
      const k = a.trim() ? targetKey(a) : ''
      if (!k || seen.has(k)) continue
      seen.add(k)
      next.push(a.trim())
    }
    setTyped(next)
  }
  const removeTyped = (entry: string) =>
    setTyped(withoutTargets(targets.customTargets, [targetKey(entry)]))
  const replaceTyped = (entry: ClassifiedTarget, next: string) =>
    setTyped(replaceEntryInLines(targets.customTargets, entry.input, next))
  // One row per target (repeats folded), the entries that are not added after.
  const listEntries = useMemo(() => {
    const seen = new Set<string>()
    const valid: ClassifiedTarget[] = []
    const bad: ClassifiedTarget[] = []
    for (const l of pasted.lines) {
      if (isRefusedKind(l.kind)) {
        bad.push(l)
        continue
      }
      if (seen.has(l.value)) continue
      seen.add(l.value)
      valid.push(l)
    }
    return [...bad, ...valid]
  }, [pasted.lines])
  const asList = listEntries.length > CHIP_LIMIT
  const largeRanges = useMemo(() => largeRangeSummary(pasted.targets), [pasted.targets])
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
        customTargets: withoutTargets(targets.customTargets, [...drop]),
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
    ...(asList
      ? []
      : listEntries.map((entry, i) =>
          isRefusedKind(entry.kind)
            ? {
                key: `i:${i}:${entry.input}`,
                label: entry.input,
                kind: 'invalid' as const,
                title: targetReasonText(t, entry),
                onRemove: () => removeTyped(entry.input),
              }
            : {
                key: `t:${entry.value}`,
                label: entry.value,
                kind: 'typed' as const,
                onRemove: () => removeTyped(entry.input),
              }
        )),
    // The *.domain targets the coverage level made of typed or picked
    // domains, and the addresses of `subdomains_ips`.
    ...sent
      .filter((x) => !asList && isWildcardTarget(x) && !pasted.targets.includes(x))
      .map((x) => ({ key: `w:${x}`, label: x, kind: 'expanded' as const })),
    ...(coverage === 'subdomains_ips' ? expansion.added : []).map((x) => ({
      key: `e:${x}`,
      label: x,
      kind: 'expanded' as const,
    })),
  ]
  const lastTyped = asList ? undefined : pasted.lines.at(-1)?.input
  const kindCounts = (Object.entries(pasted.byKind) as [TargetKind, number][]).filter(
    ([k]) => !isRefusedKind(k)
  )

  const typedKeys = useMemo(
    () => new Set(pasted.lines.map((l) => targetKey(l.input))),
    [pasted.lines]
  )
  const pickFromScope = (picked: string[], add: boolean) =>
    add
      ? addTyped(picked)
      : setTyped(
          withoutTargets(
            targets.customTargets,
            picked.map((x) => targetKey(x))
          )
        )

  // What the scan probes, by kind, each kind's setting next to it.
  const groups = useMemo(
    () =>
      groupTargets({
        typed: listEntries,
        coverage,
        assets: targets.assetIds.map((id) => ({ id, name: pickedAssets[id] })),
        groups: targets.assetGroupIds.map((id) => ({ id, name: pickedGroups[id] })),
        addedAddresses: coverage === 'subdomains_ips' ? expansion.added : [],
      }),
    [
      listEntries,
      coverage,
      targets.assetIds,
      targets.assetGroupIds,
      pickedAssets,
      pickedGroups,
      expansion.added,
    ]
  )
  // sent is rebuilt every render: key the selectors on its text.
  const sentText = sent.join('\n')
  const selectors = useMemo(
    () => selectorsOf(sentText ? sentText.split('\n') : [], targets.targetOptions),
    [sentText, targets.targetOptions]
  )
  const selectorPreview = useSelectorPreview(selectors, targets.targetOptions)
  const rowNote = (checkAs: string) => {
    const sel = selectors.find((x) => x.target === checkAs)
    if (!sel) return undefined
    const p = selectorPreview.previews.find(
      (x) => x.selector.kind === sel.kind && x.selector.value === sel.value
    )
    const text = selectorPreviewText(t, sel, p, selectorPreview)
    return p && p.recent.length > 0 ? `${text} ${recentNamesText(t, p.recent)}` : text
  }

  // The coverage level applies to domain names: typed, else picked assets.
  const coverageGroup = !showCoverage
    ? null
    : groups.some((g) => g.kind === 'domains')
      ? ('domains' as const)
      : expansion.roots.length > 0 && targets.assetIds.length > 0
        ? ('assets' as const)
        : null
  const coverageNote =
    coverage === 'host'
      ? null
      : coverage === 'subdomains'
        ? t('scans.targets.subdomainsNote', undefined, { roots: rootsLabel })
        : expansion.isLoading
          ? t('scans.targets.lookingUp')
          : expansion.added.length === 0
            ? expansion.nameCount === 0
              ? t('scans.targets.noNamesBelow', undefined, { roots: rootsLabel })
              : t('scans.targets.noRecordedAddresses', undefined, {
                  roots: rootsLabel,
                  count: expansion.nameCount,
                })
            : expansion.added.length === 1
              ? t('scans.targets.addsOne', undefined, { roots: rootsLabel })
              : t('scans.targets.addsMany', undefined, {
                  roots: rootsLabel,
                  count: expansion.added.length,
                })
  const coverageSetting = coverageGroup && (
    <div className="min-w-0 space-y-1.5">
      <ChoiceGroup<CoverageLevel>
        label={t('scans.targets.coverage')}
        value={coverage}
        onValueChange={(v) => onChange({ targets: { ...targets, coverage: v } })}
        data-testid="coverage-choice"
        options={COVERAGE_LEVELS.map((lvl) => ({
          value: lvl.id,
          label: t(`scans.coverage.${lvl.id}.short`, lvl.label),
          hint: t(`scans.coverage.${lvl.id}.hint`, lvl.hint),
        }))}
      />
      {coverageNote && (
        <p className="text-xs text-muted-foreground" aria-live="polite">
          {coverageNote}
        </p>
      )}
    </div>
  )
  const setTargetOptions = (targetOptions: NonNullable<typeof targets.targetOptions>) =>
    onChange({ targets: { ...targets, targetOptions } })
  const settings = {
    ...(coverageGroup ? { [coverageGroup]: coverageSetting } : {}),
    ...(hasCidrTarget(sent)
      ? {
          ranges: (
            <CidrModeChoice
              options={targets.targetOptions}
              onChange={setTargetOptions}
              savedScan={savedScan}
              livenessAvailable={livenessAvailable}
            />
          ),
        }
      : {}),
  }
  const openPicker = (source: PickerSource) => {
    setPickerSource(source)
    setPickerOpen(true)
  }

  const canLower = (tier: ProbeTier) => lowerIntensityAllowed(data, chosenWorkflow?.steps, tier)

  return (
    <div className="grid min-w-0 gap-6 p-4 sm:p-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] xl:gap-8">
      {/* What you scan */}
      <section className="min-w-0 space-y-2" aria-labelledby={`${fieldId}-label`}>
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
        <InvalidTargetsNote
          entries={pasted.invalid}
          onSplit={(entry, pieces) => replaceTyped(entry, pieces.join(', '))}
        />
        {largeRanges && (
          <LargeRangeConfirm
            summary={largeRanges}
            confirmed={targets.largeRangeConfirmed}
            onConfirm={(key) => onChange({ targets: { ...targets, largeRangeConfirmed: key } })}
          />
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
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-9 max-sm:min-h-11"
            onClick={() => setBulkOpen((o) => !o)}
            aria-expanded={bulkOpen}
            aria-controls={`${fieldId}-bulk`}
            data-testid="bulk-open"
          >
            <ClipboardList className="me-1.5 h-4 w-4" aria-hidden />
            {t('scans.targetsStep.pasteList')}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-9 max-sm:min-h-11"
            onClick={() =>
              openPicker(
                targets.assetGroupIds.length > 0 && targets.assetIds.length === 0
                  ? 'groups'
                  : 'assets'
              )
            }
          >
            <Plus className="me-1.5 h-4 w-4" aria-hidden />
            {t('scans.targetsStep.fromInventory')}
          </Button>
          {canReadScope && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-9 max-sm:min-h-11"
              onClick={() => openPicker('scope')}
              data-testid="from-scope"
            >
              <ShieldCheck className="me-1.5 h-4 w-4" aria-hidden />
              {t('scans.targetsStep.fromScope')}
            </Button>
          )}
        </div>
        {bulkOpen && (
          <BulkTargetsPanel
            id={`${fieldId}-bulk`}
            present={pasted.lines.map((l) => targetKey(l.input))}
            capacity={Math.max(0, MAX_DIRECT_TARGETS - sent.length)}
            maxHostBits={maxHostBits}
            onAdd={(added) => {
              addTyped(added)
              setBulkOpen(false)
            }}
            onCancel={() => setBulkOpen(false)}
          />
        )}
        {kindCounts.length > 0 && (
          <p className="text-xs text-muted-foreground" data-testid="kind-counts">
            {t('scans.targetsStep.kindCounts', undefined, {
              count: pasted.targets.length,
              kinds: kindCounts
                .map(([k, n]) => `${n} ${t(`scans.kind.${k}`, TARGET_KIND_LABELS[k])}`)
                .join(', '),
            })}
          </p>
        )}
        {asList && (
          <TargetList
            entries={listEntries}
            resultFor={check.resultFor}
            checking={check.isLoading}
            checkAvailable={check.available}
            onRemove={(entry) => removeTyped(entry.input)}
            onReplace={replaceTyped}
          />
        )}
      </section>

      {/* What the scan probes, and how to fix what it cannot */}
      <section
        className="min-w-0 space-y-3"
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
        <CoreInfraWarning targets={sent} />
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
        <TargetGroups
          groups={groups}
          resultFor={check.resultFor}
          checking={check.isLoading}
          checkAvailable={check.available}
          settings={settings}
          rowNote={rowNote}
        />
        {hasDynamicTargets(sent, targets.targetOptions) && (
          <SelectorOptions
            options={targets.targetOptions}
            onChange={setTargetOptions}
            workflow={data.mode === 'workflow'}
          />
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

      <Sheet open={pickerOpen} onOpenChange={setPickerOpen}>
        <SheetContent side="right" className="sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>
              {t(
                canReadScope
                  ? 'scans.targetsStep.pickerTitleScope'
                  : 'scans.targetsStep.pickerTitle'
              )}
            </SheetTitle>
            <SheetDescription>
              {t(
                canReadScope
                  ? 'scans.targetsStep.pickerDescriptionScope'
                  : 'scans.targetsStep.pickerDescription'
              )}
            </SheetDescription>
          </SheetHeader>
          <SheetBody>
            <Tabs value={pickerSource} onValueChange={(v) => setPickerSource(v as PickerSource)}>
              <TabsList className="w-full">
                <TabsTrigger value="assets" className="flex-1">
                  <Target aria-hidden />
                  {t('scans.targets.tabAssets')}
                  <TabsCount value={targets.assetIds.length || null} />
                </TabsTrigger>
                <TabsTrigger value="groups" className="flex-1">
                  <FolderOpen aria-hidden />
                  {t('scans.targets.tabGroups')}
                  <TabsCount value={targets.assetGroupIds.length || null} />
                </TabsTrigger>
                {canReadScope && (
                  <TabsTrigger value="scope" className="flex-1">
                    <ShieldCheck aria-hidden />
                    {t('scans.targets.tabScope')}
                  </TabsTrigger>
                )}
              </TabsList>
              <TabsContent value="assets" className="pt-3">
                <AssetSource selected={pickedAssets} onChange={setAssets} />
              </TabsContent>
              <TabsContent value="groups" className="pt-3">
                <GroupSource selected={pickedGroups} onToggle={toggleGroup} />
              </TabsContent>
              {canReadScope && (
                <TabsContent value="scope" className="pt-3">
                  <ScopeSource present={typedKeys} onChange={pickFromScope} />
                </TabsContent>
              )}
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
