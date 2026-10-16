'use client'

import { useState } from 'react'
import { Eye, Lock, Search } from 'lucide-react'
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
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { mappingApi } from '../api/use-ticket-mapping-api'
import type {
  FieldMeta,
  InboundPreview,
  ObjectKind,
  OutboundPreview,
} from '../types/ticket-mapping.types'

interface Props {
  profileId: string
  kind: ObjectKind
  fields: FieldMeta[]
  dirty: boolean
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** A field value as a person reads it: option ids become their names. */
function renderValue(v: unknown, field?: FieldMeta): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  if (Array.isArray(v)) return v.map((x) => renderValue(x, field)).join(', ')
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    if (typeof o.id === 'string') {
      const named = field?.allowed_values?.find((a) => a.id === o.id)
      if (named) return named.name
    }
    return String(o.name ?? o.value ?? o.accountId ?? o.id ?? JSON.stringify(o))
  }
  return String(v)
}

/** Previews both ways: the exact issue fields for a finding or task, and
 *  what an existing Jira issue would change in OpenCTEM. */
export function MappingPreview({ profileId, kind, fields, dirty }: Props) {
  const { t } = useTranslation()
  const [objectId, setObjectId] = useState('')
  const [out, setOut] = useState<OutboundPreview | null>(null)
  const [outErr, setOutErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [issueKey, setIssueKey] = useState('')
  const [current, setCurrent] = useState('in_progress')
  const [inb, setInb] = useState<InboundPreview | null>(null)
  const [inErr, setInErr] = useState<string | null>(null)
  const fieldName = (id: string) => fields.find((f) => f.id === id)?.name ?? id

  const runOut = async () => {
    setBusy(true)
    setOutErr(null)
    try {
      setOut(await mappingApi.preview(profileId, objectId.trim()))
    } catch (err) {
      setOut(null)
      setOutErr(getErrorMessage(err, t('ticketMapping.preview.failed', 'The preview failed')))
    } finally {
      setBusy(false)
    }
  }
  const runIn = async () => {
    setBusy(true)
    setInErr(null)
    try {
      setInb(await mappingApi.inboundPreview(profileId, issueKey.trim(), current))
    } catch (err) {
      setInb(null)
      setInErr(getErrorMessage(err, t('ticketMapping.preview.failed', 'The preview failed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6">
      {dirty && (
        <p className="text-xs text-warning">
          {t(
            'ticketMapping.preview.unsaved',
            'The preview uses the saved draft: save your changes first.'
          )}
        </p>
      )}
      <section className="grid gap-3 rounded-lg border p-4" aria-labelledby="tm-prev-out">
        <h3 id="tm-prev-out" className="text-sm font-semibold">
          {kind === 'task'
            ? t('ticketMapping.preview.outTask', 'The issue a task would create')
            : t('ticketMapping.preview.outFinding', 'The issue a finding would create')}
        </h3>
        <div className="flex flex-wrap items-end gap-2">
          <div className="grid min-w-64 flex-1 gap-1">
            <Label htmlFor="tm-prev-id">
              {kind === 'task'
                ? t('ticketMapping.preview.taskId', 'Task ID')
                : t('ticketMapping.preview.findingId', 'Finding ID')}
            </Label>
            <Input
              id="tm-prev-id"
              value={objectId}
              placeholder="00000000-0000-0000-0000-000000000000"
              onChange={(e) => setObjectId(e.target.value)}
            />
          </div>
          <Button onClick={runOut} disabled={busy || !UUID.test(objectId.trim())}>
            <Eye className="me-1 h-4 w-4" aria-hidden />
            {t('ticketMapping.preview.run', 'Preview')}
          </Button>
        </div>
        {outErr && <p className="text-sm text-destructive">{outErr}</p>}
        {out && (
          <div className="grid gap-3">
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full text-sm">
                <thead className="bg-muted/50 text-xs text-muted-foreground">
                  <tr>
                    <th className="p-2 text-start">
                      {t('ticketMapping.preview.field', 'Jira field')}
                    </th>
                    <th className="p-2 text-start">{t('ticketMapping.preview.value', 'Value')}</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(out.fields).map(([k, v]) => (
                    <tr key={k} className="border-t align-top">
                      <td className="p-2 font-medium">{fieldName(k)}</td>
                      <td className="p-2">
                        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words font-sans text-xs">
                          {renderValue(
                            v,
                            fields.find((f) => f.id === k)
                          )}
                        </pre>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {(out.dropped ?? []).length > 0 && (
              <p className="text-xs text-muted-foreground">
                {t('ticketMapping.preview.dropped', 'Not sent: {list}', {
                  list: (out.dropped ?? [])
                    .map((d) => `${fieldName(d.field_id ?? '')} (${d.message})`)
                    .join(', '),
                })}
              </p>
            )}
            {(out.notes ?? []).map((n, i) => (
              <p key={i} className="text-xs text-muted-foreground">
                {fieldName(n.field_id ?? '')}: {n.message}
              </p>
            ))}
            {out.status && (
              <p className="text-xs">
                {out.status.error
                  ? t('ticketMapping.preview.statusErr', 'Status ({state}): {error}', {
                      state: out.state,
                      error: out.status.error,
                    })
                  : t('ticketMapping.preview.statusPath', 'Status ({state}): {n} transition(s)', {
                      state: out.state,
                      n: out.status.steps?.length ?? 0,
                    })}
              </p>
            )}
          </div>
        )}
      </section>

      <section className="grid gap-3 rounded-lg border p-4" aria-labelledby="tm-prev-in">
        <h3 id="tm-prev-in" className="text-sm font-semibold">
          {t('ticketMapping.preview.in', 'What a Jira issue would change in {product}')}
        </h3>
        <div className="flex flex-wrap items-end gap-2">
          <div className="grid gap-1">
            <Label htmlFor="tm-prev-key">{t('ticketMapping.preview.issueKey', 'Issue key')}</Label>
            <Input
              id="tm-prev-key"
              value={issueKey}
              maxLength={64}
              placeholder="SEC-12"
              onChange={(e) => setIssueKey(e.target.value)}
            />
          </div>
          {kind === 'finding' && (
            <div className="grid gap-1">
              <Label htmlFor="tm-prev-cur">
                {t('ticketMapping.status.simCurrent', 'Finding is')}
              </Label>
              <Select value={current} onValueChange={setCurrent}>
                <SelectTrigger id="tm-prev-cur" className="h-9 w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {['new', 'confirmed', 'in_progress', 'fix_applied', 'resolved'].map((s) => (
                    <SelectItem key={s} value={s}>
                      {t(`ticketMapping.state.${s}`, s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <Button
            variant="outline"
            onClick={runIn}
            disabled={busy || !/^[A-Za-z][A-Za-z0-9_]*-\d+$/.test(issueKey.trim())}
          >
            <Search className="me-1 h-4 w-4" aria-hidden />
            {t('ticketMapping.preview.read', 'Read issue')}
          </Button>
        </div>
        {inErr && <p className="text-sm text-destructive">{inErr}</p>}
        {inb && (
          <div className="grid gap-2 text-sm">
            <p>
              {t('ticketMapping.preview.issueState', '{key} is {status}', {
                key: inb.issue.Key,
                status: `${inb.issue.StatusName}${inb.issue.Resolution ? ` (${inb.issue.Resolution})` : ''}`,
              })}
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="gap-1">
                {inb.decision?.needs_approval && <Lock className="h-3 w-3" aria-hidden />}
                {t(`ticketMapping.intent.${inb.intent}`, inb.intent)}
              </Badge>
              {inb.decision?.command && (
                <span>
                  {t(`ticketMapping.command.${inb.decision.command}`, inb.decision.command)}
                </span>
              )}
            </div>
            {inb.commands.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                {t('ticketMapping.preview.noFieldChanges', 'No field changes come back.')}
              </p>
            ) : (
              <ul className="grid gap-1">
                {inb.commands.map((c) => (
                  <li key={c.row_id} className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="font-mono">{c.attr}</span>
                    <span>←</span>
                    <span>{c.value}</span>
                    <Badge variant="secondary" className="gap-1">
                      {c.needs_approval && <Lock className="h-3 w-3" aria-hidden />}
                      {t(`ticketMapping.inboundCap.${c.capability}`, c.capability)}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
