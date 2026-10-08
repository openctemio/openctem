'use client'

import { useId, useState } from 'react'
import { Loader2, Pencil, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { ErrorState } from '@/features/shared'
import {
  PlanUsageTable,
  type PlanUsageTableText,
} from '@/features/plans/components/plan-usage-table'
import {
  formatLimit,
  isPlanName,
  PLAN_KEY_LABEL,
  PLAN_LABEL,
  PLAN_NAMES,
  type PlanKey,
} from '@/features/plans/lib/plan-keys'
import { deletePlanOverride, putPlanOverride, setTenantPlan, useTenantPlan } from '../api/use-plans'
import { parseLimit } from './plan-defaults-form'

const TEXT: PlanUsageTableText = {
  limit: 'Limit',
  usedColumn: 'Used',
  limitColumn: 'Allowed',
  unlimited: 'Unlimited',
  overLimit: 'Over limit',
  override: 'Set for this organization',
  until: (date) => `until ${new Date(date).toLocaleDateString()}`,
  keyLabel: (k) => PLAN_KEY_LABEL[k],
}

const MAX_REASON = 500

export interface OrganizationPlanPanelProps {
  tenantId: string
  /** Operations admins and up change the plan and set limits. */
  canManage: boolean
}

/**
 * Console > Organizations > an organization > Plan: the plan, usage per limit
 * with an over-limit badge, and limits set for this organization (a reason
 * is required, an expiry is optional). Nothing is ever removed by a lower
 * limit.
 */
export function OrganizationPlanPanel({ tenantId, canManage }: OrganizationPlanPanelProps) {
  const { data, error, isLoading, mutate } = useTenantPlan(tenantId)
  const [busyPlan, setBusyPlan] = useState(false)
  const [editing, setEditing] = useState<PlanKey | null>(null)

  if (error) {
    return <ErrorState title="the plan" error={error} onRetry={() => void mutate()} />
  }
  if (isLoading || !data) {
    return <Skeleton className="h-80 w-full" />
  }

  const changePlan = async (plan: string) => {
    setBusyPlan(true)
    try {
      await mutate(await setTenantPlan(tenantId, plan), { revalidate: false })
      toast.success(`Plan changed to ${isPlanName(plan) ? PLAN_LABEL[plan] : plan}`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not change the plan')
    } finally {
      setBusyPlan(false)
    }
  }

  const removeOverride = async (key: PlanKey) => {
    try {
      await mutate(await deletePlanOverride(tenantId, key), { revalidate: false })
      toast.success(`${PLAN_KEY_LABEL[key]}: back to the plan limit`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not remove the limit')
    }
  }

  const editingRow = editing ? data.limits?.find((l) => l.key === editing) : undefined

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-4 space-y-0">
        <div className="space-y-1.5">
          <CardTitle className="flex flex-wrap items-center gap-2">
            Plan
            {data.over_limit && <Badge variant="destructive">Over limit</Badge>}
          </CardTitle>
          <CardDescription>
            Organizations created before plans existed are Enterprise (no limits). A lower limit
            never removes anything; new additions over it are refused.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          {busyPlan && <Loader2 className="size-4 animate-spin text-muted-foreground" />}
          <Select
            value={data.plan}
            onValueChange={(v) => void changePlan(v)}
            disabled={!canManage || busyPlan}
          >
            <SelectTrigger className="w-40" aria-label="Plan">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PLAN_NAMES.map((p) => (
                <SelectItem key={p} value={p}>
                  {PLAN_LABEL[p]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </CardHeader>
      <CardContent>
        <PlanUsageTable
          limits={data.limits ?? []}
          text={TEXT}
          actionColumn={canManage ? 'Organization limit' : undefined}
          action={
            canManage
              ? (row) => (
                  <div className="flex justify-end gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditing(row.key)}
                      aria-label={`Set the ${PLAN_KEY_LABEL[row.key]} limit for this organization`}
                    >
                      <Pencil className="size-4" />
                    </Button>
                    {row.source === 'override' && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => void removeOverride(row.key)}
                        aria-label={`Use the plan limit for ${PLAN_KEY_LABEL[row.key]}`}
                      >
                        <RotateCcw className="size-4" />
                      </Button>
                    )}
                  </div>
                )
              : undefined
          }
        />
        {!canManage && (
          <p className="mt-3 text-sm text-muted-foreground">
            Changing the plan or a limit needs an operations admin.
          </p>
        )}
      </CardContent>
      {editing && (
        <OverrideDialog
          key={editing}
          tenantId={tenantId}
          planKey={editing}
          current={editingRow?.limit}
          currentReason={editingRow?.source === 'override' ? editingRow.override_reason : undefined}
          onClose={() => setEditing(null)}
          onSaved={(next) => {
            void mutate(next, { revalidate: false })
            setEditing(null)
          }}
        />
      )}
    </Card>
  )
}

function OverrideDialog({
  tenantId,
  planKey,
  current,
  currentReason,
  onClose,
  onSaved,
}: {
  tenantId: string
  planKey: PlanKey
  current?: number
  currentReason?: string
  onClose: () => void
  onSaved: (next: Awaited<ReturnType<typeof putPlanOverride>>) => void
}) {
  const id = useId()
  const [value, setValue] = useState(current === undefined || current < 0 ? '' : String(current))
  const [reason, setReason] = useState(currentReason ?? '')
  const [expires, setExpires] = useState('')
  const [busy, setBusy] = useState(false)
  // Local yyyy-mm-dd, read once when the dialog opens.
  const [today] = useState(() => {
    const d = new Date()
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
  })

  const parsed = parseLimit(value)
  const expiresAt = expires ? new Date(`${expires}T23:59:59`) : undefined
  // An expiry runs to the end of the chosen day: today is still in the future.
  const expiryBad = !!expires && expires < today
  const reasonBad = reason.trim() === '' || reason.trim().length > MAX_REASON
  const invalid = parsed === null || reasonBad || expiryBad

  const save = async () => {
    if (parsed === null) return
    setBusy(true)
    try {
      onSaved(
        await putPlanOverride(tenantId, planKey, {
          value: parsed,
          reason: reason.trim(),
          expires_at: expiresAt?.toISOString(),
        })
      )
      toast.success(`${PLAN_KEY_LABEL[planKey]} limit set for this organization`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not set the limit')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{PLAN_KEY_LABEL[planKey]} for this organization</DialogTitle>
          <DialogDescription>
            Wins over the plan limit (now {formatLimit(current, 'unlimited')}). Recorded in the
            admin audit log.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor={`${id}-v`}>Limit</Label>
              <Input
                id={`${id}-v`}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="Unlimited"
                inputMode="numeric"
                aria-invalid={parsed === null}
              />
              <p className="text-xs text-muted-foreground">Leave empty for no limit.</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-r`}>Reason</Label>
              <Textarea
                id={`${id}-r`}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={MAX_REASON}
                rows={2}
                aria-invalid={reasonBad && reason !== ''}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-e`}>Expires (optional)</Label>
              <Input
                id={`${id}-e`}
                type="date"
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
                aria-invalid={expiryBad}
              />
              {expiryBad && <p className="text-sm text-destructive">Pick a date in the future.</p>}
            </div>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void save()} disabled={invalid || busy}>
            {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
