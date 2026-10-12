'use client'

import { useEffect, useId, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  PLAN_KEY_LABEL,
  PLAN_KEYS,
  PLAN_LABEL,
  PLAN_NAMES,
  UNLIMITED,
  type PlanKey,
  type PlanName,
} from '@/features/plans/lib/plan-keys'
import type { PlanDefaultsResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import { savePlanDefaults } from '../api/use-plans'

type Grid = Record<PlanName, Record<PlanKey, string>>

function toGrid(d: PlanDefaultsResponse): Grid {
  const grid = {} as Grid
  for (const p of PLAN_NAMES) {
    grid[p] = {} as Record<PlanKey, string>
    for (const k of PLAN_KEYS) {
      const v = d.plans?.[p]?.[k]
      grid[p][k] = v === undefined || v === UNLIMITED ? '' : String(v)
    }
  }
  return grid
}

/** Empty = unlimited (-1); otherwise a whole number of 0 or more. */
export function parseLimit(v: string): number | null {
  const s = v.trim()
  if (s === '') return UNLIMITED
  if (!/^\d+$/.test(s)) return null
  const n = Number(s)
  return Number.isSafeInteger(n) ? n : null
}

export interface PlanDefaultsFormProps {
  defaults: PlanDefaultsResponse
  /** False for an administrator who may read but not change them. */
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Plans: the limits of each plan. Lowering one never removes
 * anything: organizations over it are flagged and new additions refused. A
 * change needs a fresh authenticator code and is reported to the other
 * administrators.
 */
export function PlanDefaultsForm({ defaults, canEdit, onSaved }: PlanDefaultsFormProps) {
  const initial = useMemo(() => toGrid(defaults), [defaults])
  const [grid, setGrid] = useState<Grid>(initial)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const codeId = useId()

  useEffect(() => setGrid(initial), [initial])

  const invalid = PLAN_NAMES.some((p) => PLAN_KEYS.some((k) => parseLimit(grid[p][k]) === null))
  const dirty = PLAN_NAMES.some((p) => PLAN_KEYS.some((k) => grid[p][k] !== initial[p][k]))

  const setCell = (p: PlanName, k: PlanKey, v: string) =>
    setGrid((g) => ({ ...g, [p]: { ...g[p], [k]: v } }))

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    const plans: Record<string, Record<string, number>> = {}
    for (const p of PLAN_NAMES) {
      plans[p] = {}
      for (const k of PLAN_KEYS) plans[p][k] = parseLimit(grid[p][k]) ?? UNLIMITED
    }
    try {
      await savePlanDefaults({ plans, version: defaults.version ?? 0, totp_code: code.trim() })
      setConfirmOpen(false)
      toast.success('Plan limits saved')
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setConfirmOpen(false)
      if (e instanceof AdminApiError && e.status === 409) {
        toast.error('Another administrator changed the plan limits. The latest values are shown.')
        onSaved()
        return
      }
      toast.error(e instanceof Error ? e.message : 'Could not save the plan limits')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Plan limits</CardTitle>
          <CardDescription>
            What an organization on each plan may add. Leave a cell empty for no limit. Lowering a
            limit never removes members, assets or keys: organizations over it are flagged and new
            additions are refused. A limit set on one organization wins over these.
            {defaults.builtin && ' Not saved yet: the built-in defaults apply.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Limit</TableHead>
                  {PLAN_NAMES.map((p) => (
                    <TableHead key={p}>{PLAN_LABEL[p]}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {PLAN_KEYS.map((k) => (
                  <TableRow key={k}>
                    <TableCell className="font-medium">{PLAN_KEY_LABEL[k]}</TableCell>
                    {PLAN_NAMES.map((p) => {
                      const bad = parseLimit(grid[p][k]) === null
                      return (
                        <TableCell key={p}>
                          <Input
                            value={grid[p][k]}
                            onChange={(e) => setCell(p, k, e.target.value)}
                            placeholder="Unlimited"
                            inputMode="numeric"
                            className="h-8 w-28"
                            disabled={!canEdit}
                            aria-label={`${PLAN_LABEL[p]}: ${PLAN_KEY_LABEL[k]}`}
                            aria-invalid={bad}
                          />
                        </TableCell>
                      )
                    })}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {invalid && (
            <p className="text-sm text-destructive">
              Use a whole number of 0 or more, or leave the cell empty for no limit.
            </p>
          )}
          <div className="flex justify-end">
            {canEdit ? (
              <Button
                onClick={() => {
                  setCode('')
                  setCodeError(null)
                  setConfirmOpen(true)
                }}
                disabled={!dirty || invalid || busy}
              >
                Save
              </Button>
            ) : (
              <p className="text-sm text-muted-foreground">Only a super admin can change them.</p>
            )}
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        title="Change the plan limits?"
        desc={
          <p>
            Applies to every organization on these plans that has no limit of its own. Nothing is
            removed. The change is recorded in the admin audit log and the other administrators are
            emailed.
          </p>
        }
        disabled={code.trim().length < 6}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              Saving
            </>
          ) : (
            'Confirm'
          )
        }
      >
        <div className="space-y-2">
          <Label htmlFor={codeId}>Code from your authenticator</Label>
          <Input
            id={codeId}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={8}
            aria-invalid={!!codeError}
          />
          {codeError && <p className="text-sm text-destructive">{codeError}</p>}
        </div>
      </ConfirmDialog>
    </>
  )
}
