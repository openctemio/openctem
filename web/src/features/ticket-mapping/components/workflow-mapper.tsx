'use client'

import { useMemo, useState } from 'react'
import { Lock, Play, Plus, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { CATEGORIES, layoutWorkflow, workflowEdges } from '../lib/mapping-utils'
import { mappingApi } from '../api/use-ticket-mapping-api'
import type {
  CatalogView,
  InboundRule,
  Intent,
  MappingSpec,
  ObjectKind,
  Simulation,
  StatusMap,
  StatusTarget,
  ValidationIssue,
  Workflow,
} from '../types/ticket-mapping.types'

interface Props {
  profileId: string
  kind: ObjectKind
  spec: MappingSpec
  onChange: (spec: MappingSpec) => void
  catalog: CatalogView
  workflow?: Workflow
  issues?: ValidationIssue[]
  readOnly: boolean
  dirty: boolean
}

const NONE = '__none'

/** The API's decision reasons (pkg/domain/ticketmap/status.go) → i18n keys. */
const REASON_KEYS: Record<string, string> = {
  'status not mapped': 'notMapped',
  'already in progress': 'alreadyInProgress',
  'fix already claimed; verification pending': 'claimPending',
  'finding is already closed': 'closed',
  'finding is closed; reopen it in OpenCTEM': 'reopenHere',
  'finding is already open': 'alreadyOpen',
}
const COL_W = 190
const ROW_H = 54
const NODE_W = 150
const NODE_H = 34

const CATEGORY_TONE: Record<string, string> = {
  new: 'fill-muted stroke-border',
  indeterminate: 'fill-blue-500/15 stroke-blue-500/60',
  done: 'fill-emerald-500/15 stroke-emerald-500/60',
}

/** The workflow as a graph: three category columns, transitions as edges.
 *  The highlighted path is the one the simulator found. */
function WorkflowGraph({
  workflow,
  highlight,
  selected,
}: {
  workflow: Workflow
  highlight: string[]
  selected?: string
}) {
  const { t } = useTranslation()
  const nodes = useMemo(() => layoutWorkflow(workflow, COL_W, ROW_H), [workflow])
  const { edges, global } = useMemo(() => workflowEdges(workflow), [workflow])
  const pos = new Map(nodes.map((n) => [n.status.id, n]))
  const height = Math.max(...nodes.map((n) => n.y), 0) + NODE_H + 40
  const width = COL_W * 3
  const onPath = (from: string, to: string) => {
    for (let i = 0; i + 1 < highlight.length; i++)
      if (highlight[i] === from && highlight[i + 1] === to) return true
    return false
  }
  return (
    <figure className="overflow-x-auto rounded-lg border p-3">
      <svg
        viewBox={`-10 -30 ${width + 10} ${height + 30}`}
        width={width + 10}
        height={height + 30}
        className="max-w-none"
        role="img"
        aria-label={t('ticketMapping.status.graphLabel', 'Jira workflow')}
      >
        <defs>
          <marker
            id="tm-arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" className="fill-muted-foreground" />
          </marker>
          <marker
            id="tm-arrow-hi"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" className="fill-primary" />
          </marker>
        </defs>
        {CATEGORIES.map((c, i) => (
          <text
            key={c}
            x={i * COL_W}
            y={-12}
            className="fill-muted-foreground text-[11px] font-medium uppercase"
          >
            {t(`ticketMapping.category.${c}`, c)}
          </text>
        ))}
        {edges.map((e, i) => {
          const a = pos.get(e.from)
          const b = pos.get(e.to)
          if (!a || !b) return null
          const hi = onPath(e.from, e.to)
          const x1 = a.x + (b.x >= a.x ? NODE_W : 0)
          const x2 = b.x + (b.x >= a.x ? 0 : NODE_W)
          const y1 = a.y + NODE_H / 2
          const y2 = b.y + NODE_H / 2
          const same = a.x === b.x
          const d = same
            ? `M ${a.x + NODE_W} ${y1} C ${a.x + NODE_W + 30} ${y1}, ${b.x + NODE_W + 30} ${y2}, ${b.x + NODE_W} ${y2}`
            : `M ${x1} ${y1} C ${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`
          return (
            <path
              key={i}
              d={d}
              fill="none"
              strokeWidth={hi ? 2.5 : 1}
              className={hi ? 'stroke-primary' : 'stroke-muted-foreground/50'}
              markerEnd={`url(#${hi ? 'tm-arrow-hi' : 'tm-arrow'})`}
            >
              <title>{e.name}</title>
            </path>
          )
        })}
        {nodes.map((n) => {
          const on = highlight.includes(n.status.id)
          return (
            <g key={n.status.id} transform={`translate(${n.x}, ${n.y})`}>
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={8}
                className={cn(
                  CATEGORY_TONE[n.status.category] ?? CATEGORY_TONE.new,
                  (on || selected === n.status.id) && 'stroke-primary'
                )}
                strokeWidth={on || selected === n.status.id ? 2.5 : 1}
              />
              <text x={10} y={NODE_H / 2 + 4} className="fill-foreground text-[12px]">
                {n.status.name.length > 20 ? `${n.status.name.slice(0, 19)}…` : n.status.name}
              </text>
            </g>
          )
        })}
      </svg>
      {global.length > 0 && (
        <figcaption className="mt-2 text-xs text-muted-foreground">
          {t('ticketMapping.status.global', 'From any status: {list}', {
            list: global.map((g) => `${g.name} → ${pos.get(g.to)?.status.name ?? g.to}`).join(', '),
          })}
        </figcaption>
      )}
      {(workflow.transitions ?? []).length === 0 && (
        <figcaption className="mt-2 text-xs text-muted-foreground">
          {t(
            'ticketMapping.status.noTransitions',
            'This Jira site does not expose the workflow transitions: the path is found on each issue when it moves.'
          )}
        </figcaption>
      )}
    </figure>
  )
}

/** The status mapper: OpenCTEM states → workflow statuses (outbound) and
 *  workflow statuses → intents (inbound), with the simulator. */
export function WorkflowMapper({
  profileId,
  kind,
  spec,
  onChange,
  catalog,
  workflow,
  issues,
  readOnly,
  dirty,
}: Props) {
  const { t } = useTranslation()
  const wf: Workflow = workflow ?? { statuses: [], transitions: [], resolutions: [] }
  const statuses = wf.statuses ?? []
  const resolutions = wf.resolutions ?? []
  const status = spec.status
  const [selectedState, setSelectedState] = useState<string>(catalog.states[0] ?? '')
  const [simOut, setSimOut] = useState<Simulation | null>(null)
  const [simIn, setSimIn] = useState<Simulation | null>(null)
  const [simError, setSimError] = useState<string | null>(null)
  const [simStatus, setSimStatus] = useState<string>(
    statuses.find((s) => s.category === 'done')?.id ?? ''
  )
  const [simResolution, setSimResolution] = useState<string>('')
  const [simCurrent, setSimCurrent] = useState<string>('in_progress')
  const [simFrom, setSimFrom] = useState<string>('')

  const setStatus = (s: StatusMap) => onChange({ ...spec, status: s })
  const setTarget = (state: string, target: StatusTarget | null) => {
    const out = { ...(status.outbound ?? {}) }
    if (target) out[state] = target
    else delete out[state]
    setStatus({ ...status, outbound: out })
  }
  const stateIssues = (state: string) => (issues ?? []).filter((i) => i.state === state)
  const needsApproval = (i: Intent) =>
    catalog.intents.find((x) => x.intent === i)?.needs_approval ?? false

  const highlight = useMemo(() => {
    const plan = simOut?.outbound
    if (!plan || !plan.steps) return []
    return [plan.from, ...plan.steps.map((s) => s.to)]
  }, [simOut])

  const runSim = async (input: Parameters<typeof mappingApi.simulate>[1], outbound: boolean) => {
    setSimError(null)
    const set = outbound ? setSimOut : setSimIn
    try {
      set(await mappingApi.simulate(profileId, input))
    } catch (err) {
      set(null)
      setSimError(
        getErrorMessage(err, t('ticketMapping.status.simFailed', 'The simulation failed'))
      )
    }
  }

  const inbound = status.inbound ?? []
  const setInbound = (rules: InboundRule[]) => setStatus({ ...status, inbound: rules })
  const ruleForStatus = (id: string) =>
    inbound.findIndex((r) => r.status_id === id && !r.resolution)

  const intentSelect = (value: Intent, onValue: (i: Intent) => void, id: string) => (
    <Select value={value} onValueChange={(v) => onValue(v as Intent)} disabled={readOnly}>
      <SelectTrigger id={id} className="h-8 w-64">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {catalog.intents.map((i) => (
          <SelectItem key={i.intent} value={i.intent}>
            <span className="flex items-center gap-1">
              {i.needs_approval && <Lock className="h-3 w-3" aria-hidden />}
              {t(`ticketMapping.intent.${i.intent}`, i.intent)}
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )

  return (
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4">
      <WorkflowGraph
        workflow={wf}
        highlight={highlight}
        selected={status.outbound?.[selectedState]?.status_id}
      />

      <Tabs defaultValue="outbound">
        <TabsList>
          <TabsTrigger value="outbound">
            {t('ticketMapping.status.outbound', 'OpenCTEM → Jira')}
          </TabsTrigger>
          <TabsTrigger value="inbound">
            {t('ticketMapping.status.inbound', 'Jira → OpenCTEM')}
          </TabsTrigger>
          <TabsTrigger value="simulate">
            {t('ticketMapping.status.simulator', 'Simulator')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="outbound" className="mt-4">
          <ul className="grid gap-2">
            {catalog.states.map((state) => {
              const target = status.outbound?.[state]
              const iss = stateIssues(state)
              return (
                <li
                  key={state}
                  className={cn(
                    'grid items-center gap-2 rounded-lg border p-2 md:grid-cols-[10rem_auto_minmax(0,1fr)_minmax(0,1fr)_auto]',
                    selectedState === state && 'ring-1 ring-primary',
                    iss.some((i) => i.severity === 'error') && 'border-destructive'
                  )}
                  onClick={() => setSelectedState(state)}
                >
                  <Badge variant="secondary" className="justify-self-start">
                    {t(`ticketMapping.state.${state}`, state)}
                  </Badge>
                  <span className="hidden text-muted-foreground md:inline" aria-hidden>
                    →
                  </span>
                  <Select
                    value={target?.status_id ?? NONE}
                    disabled={readOnly}
                    onValueChange={(v) => {
                      if (v === NONE) return setTarget(state, null)
                      const st = statuses.find((s) => s.id === v)
                      setTarget(state, {
                        ...(target ?? { comment: true }),
                        status_id: v,
                        name: st?.name,
                      })
                    }}
                  >
                    <SelectTrigger
                      className="h-8"
                      aria-label={t('ticketMapping.status.target', 'Jira status for {state}', {
                        state,
                      })}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>
                        {t('ticketMapping.status.noMove', 'Does not move the issue')}
                      </SelectItem>
                      {statuses.map((s) => (
                        <SelectItem key={s.id} value={s.id}>
                          {s.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select
                    value={target?.resolution || NONE}
                    disabled={readOnly || !target || resolutions.length === 0}
                    onValueChange={(v) =>
                      target && setTarget(state, { ...target, resolution: v === NONE ? '' : v })
                    }
                  >
                    <SelectTrigger
                      className="h-8"
                      aria-label={t('ticketMapping.status.resolution', 'Resolution')}
                    >
                      <SelectValue
                        placeholder={t('ticketMapping.status.resolution', 'Resolution')}
                      />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>
                        {t('ticketMapping.status.noResolution', 'No resolution')}
                      </SelectItem>
                      {resolutions.map((r) => (
                        <SelectItem key={r.id} value={r.name}>
                          {r.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <label className="flex items-center gap-1 text-xs">
                    <Switch
                      checked={target?.comment ?? false}
                      disabled={readOnly || !target}
                      onCheckedChange={(v) => target && setTarget(state, { ...target, comment: v })}
                    />
                    {t('ticketMapping.status.comment', 'Comment')}
                  </label>
                  {iss.length > 0 && (
                    <p className="text-xs text-destructive md:col-span-5">
                      {iss.map((i) => i.message).join(' · ')}
                    </p>
                  )}
                </li>
              )
            })}
          </ul>
          <div className="mt-4 grid gap-3 rounded-lg border p-3 sm:grid-cols-3">
            <div className="grid gap-1">
              <Label htmlFor="tm-verifying">
                {t('ticketMapping.status.verifyingLabel', 'Label while verifying')}
              </Label>
              <Input
                id="tm-verifying"
                value={status.verifying_label ?? ''}
                maxLength={64}
                disabled={readOnly}
                onChange={(e) =>
                  setStatus({ ...status, verifying_label: e.target.value.replace(/\s/g, '') })
                }
              />
            </div>
            <div className="grid gap-1">
              <Label htmlFor="tm-sla">
                {t('ticketMapping.status.slaLabel', 'Label when the SLA is breached')}
              </Label>
              <Input
                id="tm-sla"
                value={status.sla_breach_label ?? ''}
                maxLength={64}
                disabled={readOnly}
                onChange={(e) =>
                  setStatus({ ...status, sla_breach_label: e.target.value.replace(/\s/g, '') })
                }
              />
            </div>
            <div className="grid gap-1">
              <Label htmlFor="tm-regression">
                {t('ticketMapping.status.regression', 'On regression')}
              </Label>
              <Select
                value={status.regression || 'new_issue'}
                disabled={readOnly}
                onValueChange={(v) =>
                  setStatus({ ...status, regression: v as StatusMap['regression'] })
                }
              >
                <SelectTrigger id="tm-regression" className="h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="new_issue">
                    {t('ticketMapping.regression.new_issue', 'Open a new linked issue')}
                  </SelectItem>
                  <SelectItem value="reopen">
                    {t('ticketMapping.regression.reopen', 'Reopen the issue')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="inbound" className="mt-4">
          <p className="mb-3 text-sm text-muted-foreground">
            {t(
              'ticketMapping.status.inboundHelp',
              'A Jira status never closes a finding: Done claims a fix that OpenCTEM verifies, and the locked intents open a request that a second person approves.'
            )}
          </p>
          <ul className="grid gap-2">
            {statuses.map((s) => {
              const idx = ruleForStatus(s.id)
              const byCategory = inbound.find(
                (r) => !r.status_id && !r.resolution && r.category === s.category
              )
              const value: Intent =
                idx >= 0 ? inbound[idx].intent : (byCategory?.intent ?? 'ignore')
              const inherited = idx < 0 && !!byCategory
              return (
                <li key={s.id} className="flex flex-wrap items-center gap-3 rounded-lg border p-2">
                  <span className="w-44 truncate text-sm font-medium">{s.name}</span>
                  <Badge variant="outline">
                    {t(`ticketMapping.category.${s.category}`, s.category)}
                  </Badge>
                  <span aria-hidden className="text-muted-foreground">
                    →
                  </span>
                  {intentSelect(
                    value,
                    (i) => {
                      const rules = [...inbound]
                      if (idx >= 0) rules[idx] = { ...rules[idx], intent: i }
                      else rules.push({ status_id: s.id, intent: i })
                      setInbound(rules)
                    },
                    `tm-in-${s.id}`
                  )}
                  {needsApproval(value) && (
                    <Badge variant="secondary" className="gap-1">
                      <Lock className="h-3 w-3" aria-hidden />
                      {t('ticketMapping.status.needsApproval', 'Needs approval')}
                    </Badge>
                  )}
                  {inherited && (
                    <span className="text-xs text-muted-foreground">
                      {t('ticketMapping.status.fromCategory', 'from the category rule')}
                    </span>
                  )}
                </li>
              )
            })}
          </ul>

          <h4 className="mt-5 mb-2 text-sm font-semibold">
            {t('ticketMapping.status.byResolution', 'Rules by resolution (checked first)')}
          </h4>
          <ul className="grid gap-2">
            {inbound.map((r, i) =>
              r.resolution ? (
                <li
                  key={i}
                  className="flex flex-wrap items-center gap-2 rounded-lg border p-2 text-sm"
                >
                  <span>
                    {r.status_id
                      ? (statuses.find((s) => s.id === r.status_id)?.name ?? r.status_id)
                      : t(`ticketMapping.category.${r.category}`, r.category ?? '')}
                    {' + '}
                    {r.resolution}
                  </span>
                  <span aria-hidden>→</span>
                  {intentSelect(
                    r.intent,
                    (it) => setInbound(inbound.map((x, j) => (j === i ? { ...x, intent: it } : x))),
                    `tm-inr-${i}`
                  )}
                  {needsApproval(r.intent) && (
                    <Lock
                      className="h-3.5 w-3.5"
                      aria-label={t('ticketMapping.status.needsApproval', 'Needs approval')}
                    />
                  )}
                  {!readOnly && (
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label={t('ticketMapping.common.remove', 'Remove')}
                      onClick={() => setInbound(inbound.filter((_, j) => j !== i))}
                    >
                      <Trash2 className="h-4 w-4" aria-hidden />
                    </Button>
                  )}
                </li>
              ) : null
            )}
          </ul>
          {!readOnly && resolutions.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              className="mt-2"
              onClick={() =>
                setInbound([
                  { category: 'done', resolution: resolutions[0].name, intent: 'request_accept' },
                  ...inbound,
                ])
              }
            >
              <Plus className="me-1 h-4 w-4" aria-hidden />
              {t('ticketMapping.status.addResolutionRule', 'Add a resolution rule')}
            </Button>
          )}
        </TabsContent>

        <TabsContent value="simulate" className="mt-4 grid gap-4">
          {dirty && (
            <p className="text-xs text-amber-700 dark:text-amber-400">
              {t(
                'ticketMapping.status.simUnsaved',
                'The simulator uses the saved draft: save your changes first.'
              )}
            </p>
          )}
          <div className="grid gap-3 rounded-lg border p-3">
            <h4 className="text-sm font-semibold">
              {t('ticketMapping.status.simOut', 'When OpenCTEM changes state')}
            </h4>
            <div className="flex flex-wrap items-end gap-2">
              <div className="grid gap-1">
                <Label htmlFor="tm-sim-state">{t('ticketMapping.status.simState', 'State')}</Label>
                <Select value={selectedState} onValueChange={setSelectedState}>
                  <SelectTrigger id="tm-sim-state" className="h-9 w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {catalog.states.map((s) => (
                      <SelectItem key={s} value={s}>
                        {t(`ticketMapping.state.${s}`, s)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1">
                <Label htmlFor="tm-sim-from">
                  {t('ticketMapping.status.simFrom', 'Issue is in')}
                </Label>
                <Select
                  value={simFrom || NONE}
                  onValueChange={(v) => setSimFrom(v === NONE ? '' : v)}
                >
                  <SelectTrigger id="tm-sim-from" className="h-9 w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>
                      {t('ticketMapping.status.simFromNew', 'A new issue')}
                    </SelectItem>
                    {statuses.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button
                size="sm"
                onClick={() => runSim({ state: selectedState, from_status_id: simFrom }, true)}
              >
                <Play className="me-1 h-4 w-4" aria-hidden />
                {t('ticketMapping.status.run', 'Run')}
              </Button>
            </div>
            {simOut?.outbound && (
              <p className="text-sm" role="status">
                {simOut.outbound.error
                  ? t('ticketMapping.status.simOutError', '{state}: {error}', {
                      state: t(
                        `ticketMapping.state.${simOut.outbound.state}`,
                        simOut.outbound.state
                      ),
                      error: simOut.outbound.error,
                    })
                  : (simOut.outbound.steps ?? []).length === 0
                    ? t(
                        'ticketMapping.status.simNoMove',
                        'The issue is already there: nothing moves.'
                      )
                    : t('ticketMapping.status.simPath', 'The issue moves {path}', {
                        path: [
                          statuses.find((s) => s.id === simOut.outbound?.from)?.name ??
                            simOut.outbound.from,
                          ...(simOut.outbound.steps ?? []).map(
                            (st) =>
                              `${statuses.find((s) => s.id === st.to)?.name ?? st.to}${
                                st.fields?.resolution ? ` (${st.fields.resolution})` : ''
                              }`
                          ),
                        ].join(' → '),
                      })}
              </p>
            )}
          </div>

          {kind === 'finding' && (
            <div className="grid gap-3 rounded-lg border p-3">
              <h4 className="text-sm font-semibold">
                {t('ticketMapping.status.simIn', 'When someone moves the issue in Jira')}
              </h4>
              <div className="flex flex-wrap items-end gap-2">
                <div className="grid gap-1">
                  <Label htmlFor="tm-sim-status">
                    {t('ticketMapping.status.simStatus', 'Jira status')}
                  </Label>
                  <Select value={simStatus} onValueChange={setSimStatus}>
                    <SelectTrigger id="tm-sim-status" className="h-9 w-44">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {statuses.map((s) => (
                        <SelectItem key={s.id} value={s.id}>
                          {s.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-1">
                  <Label htmlFor="tm-sim-res">
                    {t('ticketMapping.status.resolution', 'Resolution')}
                  </Label>
                  <Select
                    value={simResolution || NONE}
                    onValueChange={(v) => setSimResolution(v === NONE ? '' : v)}
                  >
                    <SelectTrigger id="tm-sim-res" className="h-9 w-40">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>
                        {t('ticketMapping.status.noResolution', 'No resolution')}
                      </SelectItem>
                      {resolutions.map((r) => (
                        <SelectItem key={r.id} value={r.name}>
                          {r.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-1">
                  <Label htmlFor="tm-sim-cur">
                    {t('ticketMapping.status.simCurrent', 'Finding is')}
                  </Label>
                  <Select value={simCurrent} onValueChange={setSimCurrent}>
                    <SelectTrigger id="tm-sim-cur" className="h-9 w-40">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {[
                        'new',
                        'confirmed',
                        'in_progress',
                        'fix_applied',
                        'resolved',
                        'accepted',
                        'false_positive',
                      ].map((s) => (
                        <SelectItem key={s} value={s}>
                          {t(`ticketMapping.state.${s}`, s)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <Button
                  size="sm"
                  onClick={() =>
                    runSim(
                      {
                        status_id: simStatus,
                        resolution: simResolution,
                        current_state: simCurrent,
                      },
                      false
                    )
                  }
                >
                  <Play className="me-1 h-4 w-4" aria-hidden />
                  {t('ticketMapping.status.run', 'Run')}
                </Button>
              </div>
              {simIn?.intent && (
                <div className="flex flex-wrap items-center gap-2 text-sm" role="status">
                  <Badge
                    variant={needsApproval(simIn.intent) ? 'secondary' : 'outline'}
                    className="gap-1"
                  >
                    {needsApproval(simIn.intent) && <Lock className="h-3 w-3" aria-hidden />}
                    {t(`ticketMapping.intent.${simIn.intent}`, simIn.intent)}
                  </Badge>
                  <span>
                    {simIn.decision?.command
                      ? t(`ticketMapping.command.${simIn.decision.command}`, simIn.decision.command)
                      : t('ticketMapping.status.noCommand', 'Nothing changes: {reason}', {
                          reason: t(
                            `ticketMapping.reason.${REASON_KEYS[simIn.decision?.reason ?? ''] ?? 'other'}`,
                            simIn.decision?.reason ?? ''
                          ),
                        })}
                  </span>
                  {!simIn.mapped && (
                    <span className="text-xs text-amber-700 dark:text-amber-400">
                      {t('ticketMapping.status.unmapped', 'This status has no rule.')}
                    </span>
                  )}
                </div>
              )}
            </div>
          )}
          {simError && <p className="text-sm text-destructive">{simError}</p>}
        </TabsContent>
      </Tabs>
    </div>
  )
}
