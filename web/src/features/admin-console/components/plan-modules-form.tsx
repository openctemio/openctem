'use client'

import { useEffect, useId, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
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
import { PLAN_LABEL, PLAN_NAMES, type PlanName } from '@/features/plans/lib/plan-keys'
import type { PlanModulesResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import { savePlanModules } from '../api/use-plans'

/** "*" in a plan's list: every module, including ones added later. */
export const ALL_MODULES = '*'

type Selection = Record<PlanName, { all: boolean; ids: Set<string> }>

function toSelection(d: PlanModulesResponse): Selection {
  const sel = {} as Selection
  for (const p of PLAN_NAMES) {
    const ids = d.plans?.[p] ?? []
    sel[p] = {
      all: ids.includes(ALL_MODULES),
      ids: new Set(ids.filter((id) => id !== ALL_MODULES)),
    }
  }
  return sel
}

function sameSelection(a: Selection, b: Selection): boolean {
  return PLAN_NAMES.every(
    (p) =>
      a[p].all === b[p].all &&
      a[p].ids.size === b[p].ids.size &&
      [...a[p].ids].every((id) => b[p].ids.has(id))
  )
}

/** The request body: ["*"] or the chosen module ids, per plan. */
export function toPlanModules(sel: Selection): Record<string, string[]> {
  const plans: Record<string, string[]> = {}
  for (const p of PLAN_NAMES) plans[p] = sel[p].all ? [ALL_MODULES] : [...sel[p].ids].sort()
  return plans
}

export interface PlanModulesFormProps {
  data: PlanModulesResponse
  /** False for an administrator who may read but not change them. */
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Plans: which modules each plan includes. Core modules are always
 * included and not listed. Removing a module from a plan makes it
 * unavailable to that plan's organizations (their data is kept); a grant on
 * one organization wins over this. A change needs a fresh authenticator code.
 */
export function PlanModulesForm({ data, canEdit, onSaved }: PlanModulesFormProps) {
  const initial = useMemo(() => toSelection(data), [data])
  const [sel, setSel] = useState<Selection>(initial)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const codeId = useId()

  useEffect(() => setSel(initial), [initial])

  const dirty = !sameSelection(sel, initial)
  const modules = data.modules ?? []

  const toggleAll = (p: PlanName, on: boolean) =>
    setSel((s) => ({
      ...s,
      // Leaving "every module" starts from every module listed, so nothing
      // disappears by accident.
      [p]: { all: on, ids: on ? new Set() : new Set(modules.map((m) => m.id ?? '')) },
    }))
  const toggleOne = (p: PlanName, id: string, on: boolean) =>
    setSel((s) => {
      const ids = new Set(s[p].ids)
      if (on) ids.add(id)
      else ids.delete(id)
      return { ...s, [p]: { all: false, ids } }
    })

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await savePlanModules({
        plans: toPlanModules(sel),
        version: data.version ?? 0,
        totp_code: code.trim(),
      })
      setConfirmOpen(false)
      toast.success('Plan modules saved')
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setConfirmOpen(false)
      if (e instanceof AdminApiError && e.status === 409) {
        toast.error('Another administrator changed the plan modules. The latest values are shown.')
        onSaved()
        return
      }
      toast.error(e instanceof Error ? e.message : 'Could not save the plan modules')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Plan modules</CardTitle>
          <CardDescription>
            Which modules each plan includes. Core modules (assets, findings, scans, SLA, team and
            settings) are always included. A module left out of a plan is unavailable to its
            organizations; their data is kept. A module granted to one organization wins over this.
            {data.builtin && ' Not saved yet: every plan includes every module.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Module</TableHead>
                  {PLAN_NAMES.map((p) => (
                    <TableHead key={p}>{PLAN_LABEL[p]}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow>
                  <TableCell className="font-medium">Every module</TableCell>
                  {PLAN_NAMES.map((p) => (
                    <TableCell key={p}>
                      <Checkbox
                        checked={sel[p].all}
                        onCheckedChange={(v) => toggleAll(p, v === true)}
                        disabled={!canEdit}
                        aria-label={`${PLAN_LABEL[p]}: every module`}
                      />
                    </TableCell>
                  ))}
                </TableRow>
                {modules.map((m) => (
                  <TableRow key={m.id}>
                    <TableCell>
                      {m.name}
                      {m.release === 'beta' && (
                        <span className="text-muted-foreground ms-1.5 text-xs">Beta</span>
                      )}
                    </TableCell>
                    {PLAN_NAMES.map((p) => (
                      <TableCell key={p}>
                        <Checkbox
                          checked={sel[p].all || sel[p].ids.has(m.id ?? '')}
                          onCheckedChange={(v) => toggleOne(p, m.id ?? '', v === true)}
                          disabled={!canEdit || sel[p].all}
                          aria-label={`${PLAN_LABEL[p]}: ${m.name}`}
                        />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex justify-end">
            {canEdit ? (
              <Button
                onClick={() => {
                  setCode('')
                  setCodeError(null)
                  setConfirmOpen(true)
                }}
                disabled={!dirty || busy}
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
        title="Change the plan modules?"
        desc={
          <p>
            Applies at once to every organization on these plans without a grant of its own. A
            module removed from a plan becomes unavailable to them; nothing is deleted. The change
            is recorded in the admin audit log.
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
