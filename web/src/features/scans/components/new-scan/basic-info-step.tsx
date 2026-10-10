/**
 * Basic Info Step
 *
 * Step 1: name, then what to run: a single check (one scanner) or a scan
 * workflow. The starter workflows (system templates tagged "starter":
 * Discover, Discover + Vuln, Web app, Network, Code / CI) are offered first;
 * any other active workflow is one choice away. Every list comes from the
 * API: the tool registry's active scanners and the active workflow templates.
 */

'use client'

import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Badge } from '@/components/ui/badge'
import Link from '@/components/link'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { safeHref } from '@/lib/safe-href'
import {
  byReadiness,
  firstProblem,
  isRunnable,
  readinessFixHref,
  readinessLabel,
  type WorkflowReadiness,
} from '@/features/scan-workflows/lib/readiness'
import { Radar, GitBranch, Layers, ChevronRight } from 'lucide-react'
import { useMemo } from 'react'
import type { NewScanFormData } from '../../types'
import { useScanWorkflows } from '@/lib/api/scan-workflow-hooks'
import { WorkflowStagesView } from '@/features/scan-workflows/components/workflow-stages'
import { planStages } from '@/features/scan-workflows/lib/workflow-stages'
import { ScannerSelect } from '../scanner-select'
import { TENABLE_CONNECTOR_ENABLED } from '@/features/integrations/config/feature-gates'
import { TENABLE_SC_TOOL } from '@/features/integrations/lib/tenable-sc'
import { TenableScanFields } from './tenable-scan-fields'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { Module } from '@/config/route-permissions'

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
  const { t } = useTranslation()
  // Workflow scans are a module: when it is off for the organization the
  // API refuses them, so none is offered (an existing workflow scan being
  // edited keeps showing its workflow).
  const workflowsEnabled = useModuleEnabled(Module.ScanWorkflows)
  const offerWorkflows = workflowsEnabled || (lockMode && data.mode === 'workflow')
  // The workflows are needed to offer the starters, unless the mode is
  // locked to a single scan (Edit) or workflows are not offered.
  const { data: workflowsData, isLoading: isLoadingWorkflows } = useScanWorkflows(
    !offerWorkflows || (lockMode && data.mode === 'single')
      ? undefined
      : { is_active: true, per_page: 100, include: 'readiness' },
    { revalidateOnFocus: false, isPaused: () => !offerWorkflows }
  )
  // Workflows that can run here come first; the others stay visible, off,
  // with why (a hidden card would hide what the product can do).
  const workflows = useMemo(() => byReadiness(workflowsData?.data ?? []), [workflowsData?.data])
  const runnable = useMemo(() => workflows.filter((w) => isRunnable(w.readiness)), [workflows])
  const notAvailable = useMemo(() => workflows.filter((w) => !isRunnable(w.readiness)), [workflows])
  const starters = useMemo(
    () => workflows.filter((p) => p.is_system_template && (p.tags ?? []).includes('starter')),
    [workflows]
  )
  const selectedWorkflow = workflows.find((w) => w.id === data.workflowId)
  const selectedStarter = starters.find((w) => w.id === data.workflowId)
  // What the "what to run" choice shows as selected
  const choice = data.mode === 'single' ? 'single' : selectedStarter ? selectedStarter.id : 'other'
  const choose = (value: string) => {
    if (value === 'single') {
      onChange({ mode: 'single', workflowId: undefined })
    } else if (value === 'other') {
      onChange({
        mode: 'workflow',
        scannerName: '',
        workflowId: selectedStarter ? undefined : data.workflowId,
      })
    } else {
      onChange({ mode: 'workflow', scannerName: '', workflowId: value })
    }
  }

  return (
    <div className="space-y-5 px-4 sm:px-6 py-4">
      {/* Scan Name */}
      <div className="space-y-2">
        <Label htmlFor="scan-name">
          {t('scans.basic.name')} <span className="text-destructive">*</span>
        </Label>
        <Input
          id="scan-name"
          placeholder={t('scans.basic.namePlaceholder')}
          value={data.name}
          onChange={(e) => onChange({ name: e.target.value })}
        />
      </div>

      {/* What to run: a single check, a starter workflow or another workflow */}
      {!lockMode && offerWorkflows && (
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">{t('scans.basic.whatToRun')}</legend>
          <RadioGroup
            value={choice}
            onValueChange={choose}
            className="grid grid-cols-1 gap-2 sm:grid-cols-2"
          >
            <ChoiceCard
              value="single"
              title={t('scans.basic.singleCheck')}
              description={t('scans.basic.singleCheckHint')}
              icon={<Radar className="h-4 w-4" />}
            />
            {starters.map((s) => (
              <ChoiceCard
                key={s.id}
                value={s.id}
                title={s.name}
                description={s.description ?? ''}
                icon={<GitBranch className="h-4 w-4" />}
                stages={planStages(s.steps ?? []).stages.map((g) => g.map((st) => st.name))}
                readiness={s.readiness}
              />
            ))}
            <ChoiceCard
              value="other"
              title={t('scans.basic.anotherWorkflow')}
              description={t('scans.basic.anotherWorkflowHint')}
              icon={<Layers className="h-4 w-4" />}
            />
          </RadioGroup>
        </fieldset>
      )}

      {/* Single scan: the scanner, from the tool registry */}
      {data.mode === 'single' && (
        <div className="space-y-2">
          <Label htmlFor="scan-scanner">
            {t('scans.basic.scanner')} <span className="text-destructive">*</span>
          </Label>
          <ScannerSelect
            id="scan-scanner"
            value={data.scannerName}
            onChange={(scannerName) => onChange({ scannerName })}
            allowConnectors={TENABLE_CONNECTOR_ENABLED}
            zoneId={data.scanZoneId}
          />
          <p className="text-muted-foreground text-xs">
            {t('scans.basic.scannerHint')}
            {!lockMode && ` ${t('scans.basic.chainHint')}`}
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

      {/* Workflow Scan: Workflow Selection (a starter is chosen above) */}
      {data.mode === 'workflow' && (lockMode || !selectedStarter) && (
        <div className="space-y-3">
          <Label>
            {t('scans.basic.selectWorkflow')} <span className="text-destructive">*</span>
          </Label>
          <Select
            value={data.workflowId || undefined}
            onValueChange={(value) => onChange({ workflowId: value })}
          >
            <SelectTrigger aria-label={t('scans.basic.workflow')}>
              <SelectValue
                placeholder={
                  isLoadingWorkflows
                    ? t('scans.basic.loadingWorkflows')
                    : workflows.length === 0
                      ? t('scans.basic.noActiveWorkflows')
                      : t('scans.basic.chooseWorkflow')
                }
              />
            </SelectTrigger>
            <SelectContent>
              {data.workflowId && !selectedWorkflow && !isLoadingWorkflows && (
                <SelectItem value={data.workflowId}>{t('scans.basic.currentInactive')}</SelectItem>
              )}
              {runnable.map((workflow) => (
                <SelectItem key={workflow.id} value={workflow.id}>
                  <div className="flex items-center gap-2">
                    <span>{workflow.name}</span>
                    {workflow.is_system_template && (
                      <Badge variant="outline" className="text-xs">
                        {t('scans.basic.system')}
                      </Badge>
                    )}
                    {readinessLabel(workflow.readiness) && (
                      <span className="text-[10px] text-warning">
                        {readinessLabel(workflow.readiness)}
                      </span>
                    )}
                  </div>
                </SelectItem>
              ))}
              {notAvailable.length > 0 && (
                <SelectGroup>
                  <SelectLabel className="text-xs text-muted-foreground">
                    {t('scans.basic.notAvailable')}
                  </SelectLabel>
                  {notAvailable.map((workflow) => (
                    <SelectItem
                      key={workflow.id}
                      value={workflow.id}
                      disabled
                      title={firstProblem(workflow.readiness)?.reason}
                    >
                      <div className="flex items-center gap-2">
                        <span>{workflow.name}</span>
                        <span className="text-[10px] text-muted-foreground">
                          {firstProblem(workflow.readiness)?.reason ??
                            readinessLabel(workflow.readiness)}
                        </span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectGroup>
              )}
            </SelectContent>
          </Select>
          {!isLoadingWorkflows && workflows.length === 0 && (
            <p className="text-muted-foreground text-xs">
              <Link href="/scans/workflows" className="underline">
                {t('scans.basic.createWorkflow')}
              </Link>
            </p>
          )}

          {/* Selected workflow: its steps, in order */}
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
                  <span>
                    {t('scans.basic.steps', undefined, {
                      count: selectedWorkflow.steps?.length ?? 0,
                    })}
                  </span>
                </div>
                <WorkflowStagesView
                  steps={selectedWorkflow.steps ?? []}
                  maxParallel={selectedWorkflow.settings?.max_parallel_steps || 3}
                />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/** One "what to run" option: a radio with a title, a description and steps. */
function ChoiceCard({
  value,
  title,
  description,
  icon,
  stages,
  readiness,
}: {
  value: string
  title: string
  description: string
  icon: React.ReactNode
  /** Step names by stage: steps of one stage run in parallel. */
  stages?: string[][]
  readiness?: WorkflowReadiness
}) {
  const { t } = useTranslation()
  const id = `run-choice-${value}`
  const off = !isRunnable(readiness)
  const label = readinessLabel(readiness)
  const problem = firstProblem(readiness)
  const fixHref = readinessFixHref(readiness)
  return (
    <Label
      htmlFor={id}
      className={cn(
        'flex items-start gap-3 rounded-lg border p-3 font-normal has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-primary/5',
        off ? 'cursor-not-allowed opacity-60' : 'cursor-pointer hover:bg-muted/50'
      )}
    >
      <RadioGroupItem
        value={value}
        id={id}
        className="mt-0.5"
        aria-label={title}
        disabled={off}
        aria-describedby={label ? `${id}-readiness` : undefined}
      />
      <span className="min-w-0 space-y-1">
        <span className="flex items-center gap-1.5 text-sm font-medium">
          {icon}
          {title}
        </span>
        <span className="text-xs text-muted-foreground line-clamp-2">{description}</span>
        {label && (
          <span
            id={`${id}-readiness`}
            className={cn('block text-[11px]', off ? 'text-muted-foreground' : 'text-warning')}
          >
            {problem?.reason ?? label}
            {problem?.fix && fixHref && (
              <>
                {' '}
                <Link href={safeHref(fixHref) ?? '#'} className="underline">
                  {problem.fix}
                </Link>
              </>
            )}
          </span>
        )}
        {stages && stages.length > 0 && (
          <span
            className="flex flex-wrap items-center gap-0.5 text-[10px] text-muted-foreground"
            aria-label={t('scans.basic.stages')}
          >
            {stages.map((names, i) => (
              <span key={i} className="flex items-center">
                {i > 0 && <ChevronRight className="h-3 w-3" />}
                {names.length > 1
                  ? t('scans.basic.inParallel', undefined, { names: names.join(' + ') })
                  : names[0]}
              </span>
            ))}
          </span>
        )}
      </span>
    </Label>
  )
}
