/**
 * Options Step
 *
 * Only what most scans need, defaults already right: where the scan runs
 * (the sensor preference) and the scan profile (the pass/fail rule),
 * with the job size and reliability settings under Advanced.
 */

'use client'

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { ChevronDown, Cloud, Server, Sparkles } from 'lucide-react'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { Permission, useHasPermission } from '@/lib/permissions'
import { maxDurationInput } from '@/features/scans/lib/scan-form'
import { CommittedNumberInput } from '@/components/ui/committed-number-input'
import { usePlatformScanning } from '@/lib/api/platform-hooks'
import { gateSummary } from '@/features/scan-profiles/gate-summary'
import { useScanProfiles } from '@/lib/api/scan-profile-hooks'
import type { NewScanFormData, SensorPreference } from '../../types'
import { SENSOR_PREFERENCE_CONFIG } from '../../types'

interface OptionsStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
  /** Offer the scan profile (a new scan; Edit keeps the stored one). */
  showProfile?: boolean
}

const DEFAULT_PROFILE = 'default'

const PREFERENCE_ICONS: Record<SensorPreference, React.ReactNode> = {
  auto: <Sparkles className="h-4 w-4" aria-hidden />,
  tenant: <Server className="h-4 w-4" aria-hidden />,
  platform: <Cloud className="h-4 w-4" aria-hidden />,
}

export function OptionsStep({ data, onChange, showProfile = false }: OptionsStepProps) {
  const { t } = useTranslation()
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const { offered: platformOffered } = usePlatformScanning()
  const canReadProfiles = useHasPermission(Permission.ScanProfilesRead)
  const { data: profilesData } = useScanProfiles(
    showProfile && canReadProfiles ? { per_page: 100 } : undefined,
    { revalidateOnFocus: false, isPaused: () => !(showProfile && canReadProfiles) }
  )
  const profiles = profilesData?.items ?? []
  const preferences: SensorPreference[] =
    platformOffered || data.sensorPreference === 'platform'
      ? ['auto', 'tenant', 'platform']
      : ['auto', 'tenant']
  const chosenProfile = profiles.find((p) => p.id === data.profileId)

  return (
    <div className="space-y-6 p-4">
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">{t('scans.options.whereRuns')}</legend>
        <RadioGroup
          value={data.sensorPreference}
          onValueChange={(value: SensorPreference) => onChange({ sensorPreference: value })}
          className="grid gap-2 sm:grid-cols-3"
        >
          {preferences.map((p) => (
            <label
              key={p}
              htmlFor={`sensor-${p}`}
              className={cn(
                'flex cursor-pointer items-start gap-3 rounded-lg border p-3 hover:bg-muted/50',
                data.sensorPreference === p && 'border-primary bg-primary/5'
              )}
            >
              <RadioGroupItem value={p} id={`sensor-${p}`} className="mt-0.5" />
              <span className="min-w-0 space-y-0.5">
                <span className="flex items-center gap-1.5 text-sm font-medium">
                  {PREFERENCE_ICONS[p]}
                  {t(`scans.sensorPref.${p}.label`, SENSOR_PREFERENCE_CONFIG[p].label)}
                </span>
                <span className="text-muted-foreground block text-xs">
                  {t(`scans.sensorPref.${p}.description`, SENSOR_PREFERENCE_CONFIG[p].description)}
                </span>
              </span>
            </label>
          ))}
        </RadioGroup>
        <p className="text-muted-foreground text-xs">{t('scans.options.zoneNote')}</p>
      </fieldset>

      {showProfile && canReadProfiles && profiles.length > 0 && (
        <div className="space-y-2">
          <Label htmlFor="scan-profile">{t('scans.options.profile')}</Label>
          <Select
            value={data.profileId ?? DEFAULT_PROFILE}
            onValueChange={(v) => onChange({ profileId: v === DEFAULT_PROFILE ? undefined : v })}
          >
            <SelectTrigger id="scan-profile" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={DEFAULT_PROFILE}>{t('scans.options.orgDefault')}</SelectItem>
              {profiles.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                  {p.is_default ? t('scans.options.defaultSuffix') : ''}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-muted-foreground text-xs">
            {chosenProfile
              ? `${gateSummary(chosenProfile.quality_gate, t)}${chosenProfile.description ? ` · ${chosenProfile.description}` : ''}`
              : t('scans.options.profileHelp')}
          </p>
        </div>
      )}

      <Collapsible open={advancedOpen} onOpenChange={setAdvancedOpen}>
        <CollapsibleTrigger className="flex w-full items-center gap-2 border-t py-2 text-sm text-muted-foreground transition-colors hover:text-foreground">
          <ChevronDown
            className={cn('h-4 w-4 transition-transform', advancedOpen && 'rotate-180')}
            aria-hidden
          />
          {t('scans.options.advanced')}
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-4 pt-3">
          <div className="space-y-2">
            <Label htmlFor="max-concurrent">{t('scans.options.perJob')}</Label>
            <Select
              value={data.maxConcurrent.toString()}
              onValueChange={(value) => onChange({ maxConcurrent: parseInt(value, 10) })}
            >
              <SelectTrigger id="max-concurrent" className="w-full">
                <SelectValue placeholder={t('scans.options.perJobPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {Array.from(new Set([1, 5, 10, 15, 20, 25, 50, data.maxConcurrent]))
                  .sort((a, b) => a - b)
                  .map((n) => (
                    <SelectItem key={n} value={n.toString()}>
                      {t(
                        n === 1 ? 'scans.options.targetsOne' : 'scans.options.targetsMany',
                        undefined,
                        {
                          count: n,
                        }
                      )}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">{t('scans.options.perJobHelp')}</p>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="timeout-seconds" className="text-xs">
                {t('scans.options.timeout')}
              </Label>
              <CommittedNumberInput
                id="timeout-seconds"
                min={30}
                max={86400}
                value={data.timeoutSeconds}
                display={(v) => (v > 0 ? String(v) : '')}
                parse={maxDurationInput}
                onCommit={(timeoutSeconds) => onChange({ timeoutSeconds })}
              />
              <p className="text-muted-foreground text-[11px]">{t('scans.options.timeoutRange')}</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="max-retries" className="text-xs">
                {t('scans.options.maxRetries')}
              </Label>
              <CommittedNumberInput
                id="max-retries"
                min={0}
                max={10}
                value={data.maxRetries}
                parse={(text) => Math.max(0, Math.min(10, parseInt(text || '0', 10) || 0))}
                onCommit={(maxRetries) => onChange({ maxRetries })}
              />
              <p className="text-muted-foreground text-[11px]">{t('scans.options.noRetries')}</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="retry-backoff" className="text-xs">
                {t('scans.options.backoff')}
              </Label>
              <CommittedNumberInput
                id="retry-backoff"
                min={10}
                max={86400}
                value={data.retryBackoffSeconds}
                parse={(text) => Math.max(10, Math.min(86400, parseInt(text || '0', 10) || 60))}
                onCommit={(retryBackoffSeconds) => onChange({ retryBackoffSeconds })}
                disabled={data.maxRetries === 0}
              />
              <p className="text-muted-foreground text-[11px]">{t('scans.options.backoffHelp')}</p>
            </div>
          </div>
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}
