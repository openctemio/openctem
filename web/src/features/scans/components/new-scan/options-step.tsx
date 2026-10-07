/**
 * Options Step
 *
 * Step 3: how the scan is split into jobs and its reliability settings.
 * (The option checkboxes and the intensity slider that used to be here wrote
 * scanner_config keys nothing reads; scanner-specific settings belong to the
 * scan profile or the workflow step.)
 */

'use client'

import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { NewScanFormData } from '../../types'

interface OptionsStepProps {
  data: NewScanFormData
  onChange: (data: Partial<NewScanFormData>) => void
}

export function OptionsStep({ data, onChange }: OptionsStepProps) {
  return (
    <div className="space-y-6 p-4">
      {/* Targets per job (API targets_per_job) */}
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

      {/* Execution timeout & retry config — wired to backend scan_runs
          fields. Kept under a "Reliability" group so it's discoverable but not
          in the way of the main options. */}
      <div className="space-y-4 rounded-lg border p-4">
        <div>
          <Label className="text-sm font-semibold">Reliability</Label>
          <p className="text-muted-foreground text-xs mt-0.5">
            Control how long a run can take and how aggressively the platform retries failures.
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
      </div>
    </div>
  )
}
