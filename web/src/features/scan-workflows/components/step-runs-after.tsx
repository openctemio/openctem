'use client'

import { ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import type { ScanWorkflowStep } from '@/lib/api'
import { canRunAfter } from '../lib/step-deps'

/**
 * What a step runs after: the other steps, as checkboxes. A step that
 * already waits for this one is off (choosing it would make a loop). No
 * choice means the step starts with the workflow, in parallel with the
 * other first steps.
 */
export function StepRunsAfter({
  step,
  steps,
  onChange,
  disabled,
}: {
  step: ScanWorkflowStep
  steps: ScanWorkflowStep[]
  onChange: (keys: string[]) => void
  disabled?: boolean
}) {
  const current = step.depends_on ?? []
  const others = steps.filter((s) => s.id !== step.id)
  const nameOf = (key: string) => steps.find((s) => s.step_key === key)?.name || key
  const summary = current.length === 0 ? 'Start of the workflow' : current.map(nameOf).join(', ')

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild disabled={disabled || others.length === 0}>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-9 w-full justify-between font-normal"
          aria-label={`What ${step.name || step.step_key} runs after`}
        >
          <span className="truncate">{summary}</span>
          <ChevronDown className="h-3.5 w-3.5 shrink-0 opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
          Runs after these steps finish
        </DropdownMenuLabel>
        {others.map((o) => {
          const checked = current.includes(o.step_key)
          const allowed = checked || canRunAfter(steps, step.step_key, o.step_key)
          return (
            <DropdownMenuCheckboxItem
              key={o.id}
              checked={checked}
              disabled={!allowed}
              title={allowed ? undefined : `${o.name || o.step_key} already runs after this step`}
              onSelect={(e) => e.preventDefault()}
              onCheckedChange={(on) =>
                onChange(on ? [...current, o.step_key] : current.filter((k) => k !== o.step_key))
              }
            >
              <span className="truncate">{o.name || o.step_key}</span>
              {!allowed && (
                <span className="ms-auto ps-2 text-[10px] text-muted-foreground">loop</span>
              )}
            </DropdownMenuCheckboxItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
