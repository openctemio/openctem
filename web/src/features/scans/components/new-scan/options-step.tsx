/**
 * Options Step
 *
 * Only what most scans need, defaults already right: where the scan runs
 * (the sensor preference) and the scan profile (tool settings, intensity),
 * with the job size and reliability settings under Advanced.
 */

'use client'

import { useState } from 'react'
import { ChevronDown, Cloud, Server, Sparkles } from 'lucide-react'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
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
import { usePlatformScanning } from '@/lib/api/platform-hooks'
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
        <legend className="text-sm font-medium">Where it runs</legend>
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
                  {SENSOR_PREFERENCE_CONFIG[p].label}
                </span>
                <span className="text-muted-foreground block text-xs">
                  {SENSOR_PREFERENCE_CONFIG[p].description}
                </span>
              </span>
            </label>
          ))}
        </RadioGroup>
        <p className="text-muted-foreground text-xs">
          The scan zone each target goes to is shown, and can be pinned, on Review.
        </p>
      </fieldset>

      {showProfile && canReadProfiles && profiles.length > 0 && (
        <div className="space-y-2">
          <Label htmlFor="scan-profile">Scan profile</Label>
          <Select
            value={data.profileId ?? DEFAULT_PROFILE}
            onValueChange={(v) => onChange({ profileId: v === DEFAULT_PROFILE ? undefined : v })}
          >
            <SelectTrigger id="scan-profile" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={DEFAULT_PROFILE}>Organization default</SelectItem>
              {profiles.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                  {p.is_default ? ' (default)' : ''}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-muted-foreground text-xs">
            {chosenProfile
              ? `${chosenProfile.intensity} intensity${chosenProfile.description ? ` · ${chosenProfile.description}` : ''}`
              : 'Tool settings, intensity and quality gate come from the profile.'}
          </p>
        </div>
      )}

      <Collapsible open={advancedOpen} onOpenChange={setAdvancedOpen}>
        <CollapsibleTrigger className="flex w-full items-center gap-2 border-t py-2 text-sm text-muted-foreground transition-colors hover:text-foreground">
          <ChevronDown
            className={cn('h-4 w-4 transition-transform', advancedOpen && 'rotate-180')}
            aria-hidden
          />
          Advanced: job size, timeout and retries
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-4 pt-3">
          <div className="space-y-2">
            <Label htmlFor="max-concurrent">Targets per job</Label>
            <Select
              value={data.maxConcurrent.toString()}
              onValueChange={(value) => onChange({ maxConcurrent: parseInt(value, 10) })}
            >
              <SelectTrigger id="max-concurrent" className="w-full">
                <SelectValue placeholder="Select targets per job" />
              </SelectTrigger>
              <SelectContent>
                {Array.from(new Set([1, 5, 10, 15, 20, 25, 50, data.maxConcurrent]))
                  .sort((a, b) => a - b)
                  .map((n) => (
                    <SelectItem key={n} value={n.toString()}>
                      {n} {n === 1 ? 'target' : 'targets'}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">
              How many targets one sensor job scans. Smaller jobs spread a scan over more sensors;
              larger ones mean fewer jobs.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="timeout-seconds" className="text-xs">
                Timeout (seconds)
              </Label>
              <Input
                id="timeout-seconds"
                type="number"
                min={30}
                max={86400}
                value={data.timeoutSeconds}
                onChange={(e) =>
                  onChange({
                    timeoutSeconds: Math.max(
                      30,
                      Math.min(86400, parseInt(e.target.value || '0', 10) || 3600)
                    ),
                  })
                }
              />
              <p className="text-muted-foreground text-[11px]">30s – 24h</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="max-retries" className="text-xs">
                Max retries
              </Label>
              <Input
                id="max-retries"
                type="number"
                min={0}
                max={10}
                value={data.maxRetries}
                onChange={(e) =>
                  onChange({
                    maxRetries: Math.max(0, Math.min(10, parseInt(e.target.value || '0', 10) || 0)),
                  })
                }
              />
              <p className="text-muted-foreground text-[11px]">0 = no retries</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="retry-backoff" className="text-xs">
                Retry backoff (s)
              </Label>
              <Input
                id="retry-backoff"
                type="number"
                min={10}
                max={86400}
                value={data.retryBackoffSeconds}
                onChange={(e) =>
                  onChange({
                    retryBackoffSeconds: Math.max(
                      10,
                      Math.min(86400, parseInt(e.target.value || '0', 10) || 60)
                    ),
                  })
                }
                disabled={data.maxRetries === 0}
              />
              <p className="text-muted-foreground text-[11px]">Initial wait between retries</p>
            </div>
          </div>
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}
