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
import { ChevronDown } from 'lucide-react'
import { FormField, FormRow, FormStack } from '@/features/shared/components/forms'
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
import { maxDurationInput, optionsError, takesRuleSources } from '@/features/scans/lib/scan-form'
import { templateTypeForScanner } from '@/features/scans/lib/rule-templates'
import { RuleSourcesSection } from './rule-sources-section'
import { StepSettingsSection } from './step-settings-section'
import type { WorkflowPreviewRequest } from './workflow-preview'
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
  /** The workflow preview request: the step settings show each step's value from it. */
  workflowRequest?: WorkflowPreviewRequest
}

const DEFAULT_PROFILE = 'default'

export function OptionsStep({
  data,
  onChange,
  showProfile = false,
  workflowRequest,
}: OptionsStepProps) {
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
    <FormStack className="p-4">
      <FormField group label={t('scans.options.whereRuns')} hint={t('scans.options.zoneNote')}>
        <RadioGroup
          value={data.sensorPreference}
          onValueChange={(value: SensorPreference) => onChange({ sensorPreference: value })}
          className="grid grid-cols-1 gap-2 sm:grid-cols-3"
        >
          {preferences.map((p) => (
            <label
              key={p}
              htmlFor={`sensor-${p}`}
              className={cn(
                'flex cursor-pointer items-start gap-2.5 rounded-lg border border-input p-3 hover:bg-muted/50 has-[[data-state=checked]]:border-foreground has-[[data-state=checked]]:bg-foreground/5'
              )}
            >
              <RadioGroupItem value={p} id={`sensor-${p}`} className="mt-0.5" />
              <span className="min-w-0 space-y-0.5">
                <span className="block text-body font-medium">
                  {t(`scans.sensorPref.${p}.label`, SENSOR_PREFERENCE_CONFIG[p].label)}
                </span>
                <span className="block text-dense text-muted-foreground">
                  {t(`scans.sensorPref.${p}.description`, SENSOR_PREFERENCE_CONFIG[p].description)}
                </span>
              </span>
            </label>
          ))}
        </RadioGroup>
      </FormField>

      {showProfile && canReadProfiles && profiles.length > 0 && (
        <FormField
          id="scan-profile"
          label={t('scans.options.profile')}
          hint={
            chosenProfile
              ? `${gateSummary(chosenProfile.quality_gate, t)}${chosenProfile.description ? `, ${chosenProfile.description}` : ''}`
              : t('scans.options.profileHelp')
          }
        >
          {(control) => (
            <Select
              value={data.profileId ?? DEFAULT_PROFILE}
              onValueChange={(v) => onChange({ profileId: v === DEFAULT_PROFILE ? undefined : v })}
            >
              <SelectTrigger id={control.id} className="w-full">
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
          )}
        </FormField>
      )}

      {takesRuleSources(data) && (
        <RuleSourcesSection
          templateType={templateTypeForScanner(data.scannerName)!}
          ruleSources={data.ruleSources}
          customTemplateIds={data.customTemplateIds}
          onChange={onChange}
          error={optionsError(data, t)}
        />
      )}

      {data.mode === 'workflow' && data.workflowId && workflowRequest && (
        <StepSettingsSection
          workflowId={data.workflowId}
          request={workflowRequest}
          value={data.stepParams}
          onChange={(stepParams) => onChange({ stepParams })}
        />
      )}

      <Collapsible open={advancedOpen} onOpenChange={setAdvancedOpen}>
        <CollapsibleTrigger className="flex w-full items-center gap-2 border-t py-2 text-sm text-muted-foreground transition-colors hover:text-foreground">
          <ChevronDown
            className={cn('h-4 w-4 transition-transform', advancedOpen && 'rotate-180')}
            aria-hidden
          />
          {t('scans.options.advanced')}
        </CollapsibleTrigger>
        <CollapsibleContent className="flex flex-col gap-4 pt-3">
          <FormField
            id="max-concurrent"
            label={t('scans.options.perJob')}
            required={false}
            hint={t('scans.options.perJobHelp')}
          >
            {(control) => (
              <Select
                value={data.maxConcurrent.toString()}
                onValueChange={(value) => onChange({ maxConcurrent: parseInt(value, 10) })}
              >
                <SelectTrigger id={control.id} className="w-full">
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
            )}
          </FormField>

          <FormRow>
            <FormField
              id="timeout-seconds"
              label={t('scans.options.timeout')}
              required={false}
              hint={t('scans.options.timeoutRange')}
            >
              {(control) => (
                <CommittedNumberInput
                  id={control.id}
                  min={30}
                  max={86400}
                  value={data.timeoutSeconds}
                  display={(v) => (v > 0 ? String(v) : '')}
                  parse={maxDurationInput}
                  onCommit={(timeoutSeconds) => onChange({ timeoutSeconds })}
                />
              )}
            </FormField>
            <FormField
              id="max-retries"
              label={t('scans.options.maxRetries')}
              required={false}
              hint={t('scans.options.noRetries')}
            >
              {(control) => (
                <CommittedNumberInput
                  id={control.id}
                  min={0}
                  max={10}
                  value={data.maxRetries}
                  parse={(text) => Math.max(0, Math.min(10, parseInt(text || '0', 10) || 0))}
                  onCommit={(maxRetries) => onChange({ maxRetries })}
                />
              )}
            </FormField>
            <FormField
              id="retry-backoff"
              label={t('scans.options.backoff')}
              required={false}
              hint={t('scans.options.backoffHelp')}
            >
              {(control) => (
                <CommittedNumberInput
                  id={control.id}
                  min={10}
                  max={86400}
                  value={data.retryBackoffSeconds}
                  parse={(text) => Math.max(10, Math.min(86400, parseInt(text || '0', 10) || 60))}
                  onCommit={(retryBackoffSeconds) => onChange({ retryBackoffSeconds })}
                  disabled={data.maxRetries === 0}
                />
              )}
            </FormField>
          </FormRow>
        </CollapsibleContent>
      </Collapsible>
    </FormStack>
  )
}
