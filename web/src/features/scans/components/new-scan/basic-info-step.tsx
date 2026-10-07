/**
 * Basic Info Step
 *
 * Step 1: name, then the scanner (single) or a pipeline (workflow). Both lists
 * come from the API: the tool registry's active scanners and the tenant's
 * active pipeline templates. (They used to be a fixed "scan type" radio that
 * changed nothing and a hardcoded list of example workflows the API rejects.)
 */

'use client'

import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Badge } from '@/components/ui/badge'
import Link from 'next/link'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import {
  Radar,
  GitBranch,
  Layers,
  ChevronRight,
  ChevronDown,
  Sparkles,
  Server,
  Cloud,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import type { ScanMode, SensorPreference, NewScanFormData } from '../../types'
import { SCAN_MODE_CONFIG, SENSOR_PREFERENCE_CONFIG } from '../../types'
import { usePipelines } from '@/lib/api/pipeline-hooks'
import { ScannerSelect } from '../scanner-select'
import { TENABLE_CONNECTOR_ENABLED } from '@/features/integrations/config/feature-gates'
import { TENABLE_SC_TOOL } from '@/features/integrations/lib/tenable-sc'
import { TenableScanFields } from './tenable-scan-fields'

interface BasicInfoStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
  /**
   * Edit: the API cannot change a configuration between single and workflow
   * (scan_type is fixed), so the mode switch is not offered.
   */
  lockMode?: boolean
}

export function BasicInfoStep({ data, onChange, lockMode = false }: BasicInfoStepProps) {
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const { data: pipelinesData, isLoading: isLoadingPipelines } = usePipelines(
    data.mode === 'workflow' ? { is_active: true, per_page: 100 } : undefined,
    { revalidateOnFocus: false }
  )
  const pipelines = useMemo(() => pipelinesData?.items ?? [], [pipelinesData?.items])
  const selectedWorkflow = pipelines.find((w) => w.id === data.workflowId)

  return (
    <div className="space-y-5 px-4 sm:px-6 py-4">
      {/* Scan Name */}
      <div className="space-y-2">
        <Label htmlFor="scan-name">
          Scan Name <span className="text-destructive">*</span>
        </Label>
        <Input
          id="scan-name"
          placeholder="e.g., Production Security Scan"
          value={data.name}
          onChange={(e) => onChange({ name: e.target.value })}
        />
      </div>

      {/* Single scan: the scanner, from the tool registry */}
      {data.mode === 'single' && (
        <div className="space-y-2">
          <Label htmlFor="scan-scanner">
            Scanner <span className="text-destructive">*</span>
          </Label>
          <ScannerSelect
            id="scan-scanner"
            value={data.scannerName}
            onChange={(scannerName) => onChange({ scannerName })}
            allowConnectors={TENABLE_CONNECTOR_ENABLED}
            zoneId={data.scanZoneId}
          />
          <p className="text-muted-foreground text-xs">
            Active scanners in the tool registry. A scanner no online sensor can run is listed but
            off. Use Workflow mode (Advanced options) to chain several tools.
          </p>
        </div>
      )}

      {/* A Tenable.sc scan: the connector, policy and repository it launches with */}
      {data.mode === 'single' && data.scannerName === TENABLE_SC_TOOL && (
        <TenableScanFields
          value={data.scannerConfig}
          onChange={(scannerConfig) => onChange({ scannerConfig })}
        />
      )}

      {/* Workflow Scan: Workflow Selection */}
      {data.mode === 'workflow' && (
        <div className="space-y-3">
          <Label>
            Select Workflow <span className="text-destructive">*</span>
          </Label>
          <Select
            value={data.workflowId || undefined}
            onValueChange={(value) => onChange({ workflowId: value })}
          >
            <SelectTrigger aria-label="Workflow">
              <SelectValue
                placeholder={
                  isLoadingPipelines
                    ? 'Loading pipelines…'
                    : pipelines.length === 0
                      ? 'No active pipelines'
                      : 'Choose a pipeline'
                }
              />
            </SelectTrigger>
            <SelectContent>
              {data.workflowId && !selectedWorkflow && !isLoadingPipelines && (
                <SelectItem value={data.workflowId}>Current pipeline (not active)</SelectItem>
              )}
              {pipelines.map((workflow) => (
                <SelectItem key={workflow.id} value={workflow.id}>
                  <div className="flex items-center gap-2">
                    <span>{workflow.name}</span>
                    {workflow.is_system_template && (
                      <Badge variant="outline" className="text-xs">
                        System
                      </Badge>
                    )}
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {!isLoadingPipelines && pipelines.length === 0 && (
            <p className="text-muted-foreground text-xs">
              Create one under{' '}
              <Link href="/pipelines" className="underline">
                Pipelines
              </Link>
              .
            </p>
          )}

          {/* Selected pipeline: its steps, in order */}
          {selectedWorkflow && (
            <div className="rounded-lg border bg-card p-4 space-y-3">
              <div className="min-w-0">
                <h4 className="font-medium truncate">{selectedWorkflow.name}</h4>
                {selectedWorkflow.description && (
                  <p className="text-sm text-muted-foreground line-clamp-2">
                    {selectedWorkflow.description}
                  </p>
                )}
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <Layers className="h-4 w-4 shrink-0" />
                  <span>Steps ({selectedWorkflow.steps?.length ?? 0})</span>
                </div>
                {(selectedWorkflow.steps?.length ?? 0) > 0 && (
                  <div className="rounded-lg bg-muted/50 p-2">
                    <div className="flex flex-wrap items-center gap-1">
                      {selectedWorkflow.steps.map((step, index) => (
                        <div key={step.id} className="flex items-center">
                          <Badge variant="secondary" className="text-xs">
                            {index + 1}. {step.tool || step.name}
                          </Badge>
                          {index < selectedWorkflow.steps.length - 1 && (
                            <ChevronRight className="h-3 w-3 text-muted-foreground mx-0.5" />
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Advanced Options - Collapsible */}
      <Collapsible open={advancedOpen} onOpenChange={setAdvancedOpen}>
        <CollapsibleTrigger className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors w-full py-2 border-t">
          <ChevronDown
            className={`h-4 w-4 transition-transform ${advancedOpen ? 'rotate-180' : ''}`}
          />
          <span>Advanced Options</span>
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-4 pt-3">
          {/* Scan Mode (not changeable on an existing configuration) */}
          {!lockMode && (
            <div className="space-y-2">
              <Label className="text-sm">Scan Mode</Label>
              <RadioGroup
                value={data.mode}
                onValueChange={(value: ScanMode) =>
                  onChange({
                    mode: value,
                    workflowId: value === 'single' ? undefined : data.workflowId,
                    scannerName: value === 'workflow' ? '' : data.scannerName,
                  })
                }
                className="flex flex-wrap gap-3"
              >
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="single" id="mode-single" />
                  <Label htmlFor="mode-single" className="cursor-pointer text-sm font-normal">
                    <span className="flex items-center gap-1.5">
                      <Radar className="h-3.5 w-3.5" />
                      {SCAN_MODE_CONFIG.single.label}
                    </span>
                  </Label>
                </div>
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="workflow" id="mode-workflow" />
                  <Label htmlFor="mode-workflow" className="cursor-pointer text-sm font-normal">
                    <span className="flex items-center gap-1.5">
                      <GitBranch className="h-3.5 w-3.5" />
                      {SCAN_MODE_CONFIG.workflow.label}
                    </span>
                  </Label>
                </div>
              </RadioGroup>
            </div>
          )}

          {/* Sensor Preference - Compact */}
          <div className="space-y-2">
            <Label className="text-sm">Sensor Preference</Label>
            <RadioGroup
              value={data.sensorPreference}
              onValueChange={(value: SensorPreference) => onChange({ sensorPreference: value })}
              className="flex flex-wrap gap-3"
            >
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="auto" id="sensor-auto" />
                <Label htmlFor="sensor-auto" className="cursor-pointer text-sm font-normal">
                  <span className="flex items-center gap-1.5">
                    <Sparkles className="h-3.5 w-3.5" />
                    {SENSOR_PREFERENCE_CONFIG.auto.label}
                  </span>
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="tenant" id="sensor-tenant" />
                <Label htmlFor="sensor-tenant" className="cursor-pointer text-sm font-normal">
                  <span className="flex items-center gap-1.5">
                    <Server className="h-3.5 w-3.5" />
                    {SENSOR_PREFERENCE_CONFIG.tenant.label}
                  </span>
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="platform" id="sensor-platform" />
                <Label htmlFor="sensor-platform" className="cursor-pointer text-sm font-normal">
                  <span className="flex items-center gap-1.5">
                    <Cloud className="h-3.5 w-3.5" />
                    {SENSOR_PREFERENCE_CONFIG.platform.label}
                  </span>
                </Label>
              </div>
            </RadioGroup>
          </div>
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}
