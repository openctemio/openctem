'use client'

import { AlertTriangle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability } from '../lib/capability-graph'
import { withSelection, type ToolSelection } from '../lib/step-settings'

/**
 * How a capability step picks its tool: any tool, preferred tools in order,
 * or one pinned tool. Shared by the builder's inspector and the form.
 */
export function ToolSelectionField({
  step,
  capability,
  mode,
  missing,
  readOnly,
  onChange,
}: {
  step: ScanWorkflowStep
  capability: Capability
  mode: ToolSelection
  missing: Record<string, string[]>
  readOnly?: boolean
  onChange: (step: ScanWorkflowStep) => void
}) {
  const prefer = step.prefer_tools ?? []
  return (
    <section className="space-y-2">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Tool</h3>
      <RadioGroup
        value={mode}
        disabled={readOnly}
        onValueChange={(v) => {
          const next = v as ToolSelection
          const tools =
            next === 'pin'
              ? [step.tool || capability.defaultTool]
              : next === 'prefer'
                ? capability.tools
                : []
          onChange(withSelection(step, capability, next, tools))
        }}
        className="gap-2"
      >
        <label className="flex items-start gap-2 text-sm">
          <RadioGroupItem value="auto" aria-label="Any tool" className="mt-0.5" />
          <span>
            Any tool
            <span className="block text-xs text-muted-foreground">
              The platform picks an available tool, {capability.defaultTool || 'the default'} first.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <RadioGroupItem value="prefer" aria-label="Preferred tools" className="mt-0.5" />
          <span>
            Preferred tools, in order
            <span className="block text-xs text-muted-foreground">
              Only these, tried in this order.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <RadioGroupItem value="pin" aria-label="One tool" className="mt-0.5" />
          <span>
            One tool
            <span className="block text-xs text-muted-foreground">Always this tool.</span>
          </span>
        </label>
      </RadioGroup>

      {mode === 'pin' && (
        <Select
          value={step.tool}
          disabled={readOnly}
          onValueChange={(t) => onChange(withSelection(step, capability, 'pin', [t]))}
        >
          <SelectTrigger aria-label="Pinned tool" className="h-8 text-xs">
            <SelectValue placeholder="Choose a tool" />
          </SelectTrigger>
          <SelectContent>
            {capability.tools.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      {mode === 'prefer' && (
        <ul className="space-y-1">
          {capability.tools.map((t) => {
            const idx = prefer.indexOf(t)
            return (
              <li key={t} className="flex items-center gap-2 text-sm">
                <Checkbox
                  id={`${step.id}-prefer-${t}`}
                  checked={idx >= 0}
                  disabled={readOnly}
                  onCheckedChange={(on) => {
                    const next = on ? [...prefer, t] : prefer.filter((x) => x !== t)
                    onChange(
                      withSelection(step, capability, next.length > 0 ? 'prefer' : 'auto', next)
                    )
                  }}
                />
                <Label htmlFor={`${step.id}-prefer-${t}`} className="font-normal">
                  {t}
                </Label>
                {idx >= 0 && (
                  <Badge variant="secondary" className="ms-auto px-1 py-0 text-[10px]">
                    {idx + 1}
                  </Badge>
                )}
              </li>
            )
          })}
        </ul>
      )}

      {Object.entries(missing).map(([tool, params]) => (
        <p key={tool} className="flex items-start gap-1.5 text-xs text-warning">
          <AlertTriangle className="mt-px h-3 w-3 shrink-0" />
          <span>
            {tool} does not take {params.join(', ')}, so it cannot run this step with these
            settings.
          </span>
        </p>
      ))}
    </section>
  )
}
