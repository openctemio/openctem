/**
 * Targets Step
 *
 * One target picker with three sources (inventory assets, asset groups,
 * pasted targets), the coverage level for typed and picked domains, and a
 * selection summary pinned under them with the server's scope check.
 * Research: research/85-new-scan.md §4.3-4.4.
 */

'use client'

import { useEffect, useEffectEvent, useMemo, useState } from 'react'
import { FileText, FolderOpen, Target } from 'lucide-react'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import type { NewScanFormData } from '../../types'
import { COVERAGE_LEVELS, type CoverageLevel } from '../../lib/coverage-expansion'
import { useCoverageExpansion } from '../../hooks/use-coverage-expansion'
import { firstWildcard, scannerTakesWildcard } from '../../lib/wildcard-targets'
import { parsePastedTargets } from '../../lib/target-format'
import { directTargets } from '../../lib/scan-form'
import { WildcardTargetHint } from './wildcard-target-hint'
import { AssetSource, type PickedAsset } from '../target-picker/asset-source'
import { GroupSource } from '../target-picker/group-source'
import { PasteSource } from '../target-picker/paste-source'
import { SelectionSummary, type SelectionChip } from '../target-picker/selection-summary'

interface TargetsStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
  /** Offer the coverage level (new scans; an edit keeps the stored targets). */
  showCoverage?: boolean
}

type Source = 'assets' | 'groups' | 'paste'

export function TargetsStep({ data, onChange, showCoverage = true }: TargetsStepProps) {
  const targets = data.targets
  const [source, setSource] = useState<Source>(() =>
    targets.customTargets.length > 0 && targets.assetIds.length === 0
      ? 'paste'
      : targets.assetGroupIds.length > 0 && targets.assetIds.length === 0
        ? 'groups'
        : 'assets'
  )
  const groupNames = useMemo(() => targets.assetGroupNames ?? {}, [targets.assetGroupNames])
  const pickedGroups = useMemo(
    () =>
      Object.fromEntries(targets.assetGroupIds.map((id) => [id, groupNames[id] ?? 'Asset group'])),
    [targets.assetGroupIds, groupNames]
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
    const ids = new Set(targets.assetIds)
    for (const a of assets) {
      if (picked) {
        ids.add(a.id)
        names[a.id] = a.name
      } else {
        ids.delete(a.id)
        delete names[a.id]
      }
    }
    onChange({ targets: { ...targets, assetIds: [...ids], assetNames: names } })
  }
  const toggleGroup = (group: { id: string; name: string }, picked: boolean) => {
    const names = { ...groupNames }
    const ids = new Set(targets.assetGroupIds)
    if (picked) {
      ids.add(group.id)
      names[group.id] = group.name
    } else {
      ids.delete(group.id)
      delete names[group.id]
    }
    onChange({ targets: { ...targets, assetGroupIds: [...ids], assetGroupNames: names } })
  }
  const setTyped = (lines: string[]) => onChange({ targets: { ...targets, customTargets: lines } })

  // A wildcard pattern for an active single scanner: offer discovery of the
  // root, or the known assets that match (the API would refuse the pattern).
  const wildcard =
    data.mode === 'single' && !scannerTakesWildcard(data.scannerName)
      ? firstWildcard(pasted.targets)
      : null

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

  const sent = directTargets(data)
  const sensorPreference =
    data.sensorPreference === 'tenant' || data.sensorPreference === 'platform'
      ? data.sensorPreference
      : 'auto'

  const chips: SelectionChip[] = [
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
    ...pasted.targets.map((t) => ({
      key: `t:${t}`,
      label: t,
      kind: 'typed' as const,
      onRemove: () =>
        setTyped(
          targets.customTargets.filter((line) => line.trim().toLowerCase() !== t.toLowerCase())
        ),
    })),
    ...(coverage === 'host' ? [] : expansion.added).map((t) => ({
      key: `e:${t}`,
      label: t,
      kind: 'expanded' as const,
    })),
  ]

  return (
    <div className="space-y-4 p-4">
      <Tabs value={source} onValueChange={(v) => setSource(v as Source)}>
        <TabsList className="w-full">
          <TabsTrigger value="assets" className="flex-1">
            <Target className="h-4 w-4" aria-hidden />
            Assets
            <TabsCount value={targets.assetIds.length || null} />
          </TabsTrigger>
          <TabsTrigger value="groups" className="flex-1">
            <FolderOpen className="h-4 w-4" aria-hidden />
            Groups
            <TabsCount value={targets.assetGroupIds.length || null} />
          </TabsTrigger>
          <TabsTrigger value="paste" className="flex-1">
            <FileText className="h-4 w-4" aria-hidden />
            Paste
            <TabsCount
              value={pasted.lines.length || null}
              tone={pasted.invalid.length > 0 ? 'danger' : 'default'}
            />
          </TabsTrigger>
        </TabsList>
        <TabsContent value="assets" className="pt-3">
          <AssetSource selected={pickedAssets} onChange={setAssets} />
        </TabsContent>
        <TabsContent value="groups" className="pt-3">
          <GroupSource selected={pickedGroups} onToggle={toggleGroup} />
        </TabsContent>
        <TabsContent value="paste" className="pt-3">
          <PasteSource value={targets.customTargets} onChange={setTyped}>
            {wildcard && (
              <WildcardTargetHint
                pattern={wildcard}
                targets={targets.customTargets}
                onDiscover={(scannerName, next) =>
                  onChange({
                    mode: 'single',
                    scannerName,
                    targets: { ...targets, customTargets: next },
                  })
                }
                onUseAssets={(next) => onChange({ targets: { ...targets, customTargets: next } })}
              />
            )}
          </PasteSource>
        </TabsContent>
      </Tabs>

      {/* Coverage level (research/48 §6.7) */}
      {showCoverage && typedTargets.length > 0 && (
        <fieldset className="space-y-2 rounded-lg border p-3">
          <legend className="px-1 text-sm font-medium">Coverage</legend>
          <RadioGroup
            value={coverage}
            onValueChange={(v) =>
              onChange({ targets: { ...targets, coverage: v as CoverageLevel } })
            }
            className="gap-2"
          >
            {COVERAGE_LEVELS.map((lvl) => (
              <label
                key={lvl.id}
                className="flex cursor-pointer items-start gap-3 rounded-md p-2 hover:bg-muted/50"
              >
                <RadioGroupItem value={lvl.id} className="mt-0.5" aria-label={lvl.label} />
                <span className="min-w-0">
                  <span className="block text-sm">{lvl.label}</span>
                  <span className="block text-xs text-muted-foreground">{lvl.hint}</span>
                </span>
              </label>
            ))}
          </RadioGroup>
          {coverage !== 'host' && (
            <p className="text-xs text-muted-foreground" aria-live="polite">
              {expansion.isLoading
                ? 'Looking up your inventory…'
                : expansion.roots.length === 0
                  ? 'No domain names to expand: enter or pick a domain.'
                  : expansion.added.length === 0
                    ? `Nothing in your inventory below ${expansion.roots.join(', ')} yet.`
                    : `Adds ${expansion.added.length} ${expansion.added.length === 1 ? 'target' : 'targets'} from your inventory below ${expansion.roots.join(', ')}.`}
            </p>
          )}
        </fieldset>
      )}

      <SelectionSummary
        targets={sent}
        chips={chips}
        groupCount={targets.assetGroupIds.length}
        invalidCount={pasted.invalid.length}
        sensorPreference={sensorPreference}
        scannerName={data.mode === 'single' ? data.scannerName : undefined}
      />
    </div>
  )
}
