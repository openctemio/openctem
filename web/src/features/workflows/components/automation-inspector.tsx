'use client'

import { useEffect, useState } from 'react'
import { Trash2 } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'

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
import { Textarea } from '@/components/ui/textarea'
import { useScanConfigs } from '@/lib/api/scan-hooks'
import {
  AUTOMATION_STATUS_TARGETS,
  type WorkflowCatalog,
  type WorkflowCatalogEntry,
  type WorkflowNodeConfig,
} from '@/lib/api/workflow-types'
import { PERSON_CLOSURE_REASONS, closureReasonLabel } from '@/features/findings/lib/closure'
import type { AutomationNode, AutomationNodeData } from '../lib/automation-graph'
import { catalogEntriesFor, removedTypeOf } from '../lib/automation-lifecycle'
import { useAutomationLabels } from '../lib/use-automation-labels'

/** Comma-separated tags as a list, trimmed, without blanks. */
export function parseTags(text: string): string[] {
  return text
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean)
}

/** A JSON object from text, or an error code. Empty text is {}. */
export function parseConfigJson(
  text: string
): { ok: true; value: Record<string, unknown> } | { ok: false; error: 'notObject' | 'invalid' } {
  if (!text.trim()) return { ok: true, value: {} }
  try {
    const v: unknown = JSON.parse(text)
    if (v === null || typeof v !== 'object' || Array.isArray(v)) {
      return { ok: false, error: 'notObject' }
    }
    return { ok: true, value: v as Record<string, unknown> }
  } catch {
    return { ok: false, error: 'invalid' }
  }
}

function JsonField({
  id,
  label,
  value,
  onChange,
}: {
  id: string
  label: string
  value: Record<string, unknown> | undefined
  onChange: (v: Record<string, unknown>) => void
}) {
  const { t } = useTranslation()
  const [text, setText] = useState(() => (value ? JSON.stringify(value, null, 2) : ''))
  const [error, setError] = useState<'notObject' | 'invalid' | null>(null)
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Textarea
        id={id}
        rows={4}
        className="font-mono text-xs"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onBlur={() => {
          const r = parseConfigJson(text)
          if (r.ok) {
            setError(null)
            onChange(r.value)
          } else setError(r.error)
        }}
      />
      {error && (
        <p className="text-xs text-destructive">
          {error === 'notObject'
            ? t(
                'automations.inspector.jsonNotObject',
                'Enter a JSON object, for example {"key": "value"}.'
              )
            : t('automations.inspector.jsonInvalid', 'This is not valid JSON.')}
        </p>
      )}
    </div>
  )
}

function SavedScanSelect({ value, onChange }: { value?: string; onChange: (id: string) => void }) {
  const { t } = useTranslation()
  const { data, isLoading } = useScanConfigs({ per_page: 100, sort: 'name' })
  const scans = data?.data ?? []
  return (
    <div className="space-y-1.5">
      <Label>{t('automations.inspector.savedScan', 'Saved scan')}</Label>
      <Select value={value ?? ''} onValueChange={onChange}>
        <SelectTrigger aria-label={t('automations.inspector.savedScan', 'Saved scan')}>
          <SelectValue
            placeholder={
              isLoading
                ? t('automations.inspector.loadingScans', 'Loading scans...')
                : t('automations.inspector.chooseScan', 'Choose a saved scan')
            }
          />
        </SelectTrigger>
        <SelectContent>
          {scans.map((s) => (
            <SelectItem key={s.id} value={s.id}>
              {s.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {!isLoading && scans.length === 0 && (
        <p className="text-xs text-muted-foreground">
          {t('automations.inspector.noScans', 'No saved scan yet. Create one in Scans.')}
        </p>
      )}
    </div>
  )
}

/**
 * A type picker fed by the catalog alone. An entry the caller lacks the
 * permission for is listed disabled with that permission; a stored type the
 * catalog no longer lists shows as a removed type.
 */
function CatalogTypeSelect({
  label,
  placeholder,
  entries,
  value,
  removed,
  name,
  disabled,
  onChange,
}: {
  label: string
  placeholder: string
  entries: WorkflowCatalogEntry[]
  value: string | undefined
  removed: string | undefined
  name: (type: string) => string
  disabled?: boolean
  onChange: (type: string) => void
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Select value={removed ? '' : (value ?? '')} onValueChange={onChange} disabled={disabled}>
        <SelectTrigger aria-label={label}>
          <SelectValue placeholder={placeholder} />
        </SelectTrigger>
        <SelectContent>
          {entries.map((e) => (
            <SelectItem key={e.type} value={e.type} disabled={!e.allowed}>
              <span>{name(e.type)}</span>
              {!e.allowed && (
                <span className="ms-2 text-xs text-muted-foreground">
                  {e.permission
                    ? t('automations.canvas.needsPermission', 'Needs {permission}', {
                        permission: e.permission,
                      })
                    : t('automations.canvas.notAllowed', 'Not allowed for you')}
                </span>
              )}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {removed && (
        <p className="text-xs text-warning" data-testid="inspector-removed-type">
          {t(
            'automations.inspector.removedType',
            'Removed type: {id}. The platform no longer runs it; choose another before going live.',
            { id: removed }
          )}
        </p>
      )}
    </div>
  )
}

/** Fields of the two request actions: a person decides on what they create. */
function RequestFields({
  type,
  ac,
  disabled,
  onChange,
}: {
  type: 'request_false_positive' | 'request_risk_acceptance'
  ac: Record<string, unknown>
  disabled?: boolean
  onChange: (ac: Record<string, unknown>) => void
}) {
  const { t } = useTranslation()
  const reasons =
    (type === 'request_false_positive'
      ? PERSON_CLOSURE_REASONS.false_positive
      : PERSON_CLOSURE_REASONS.accepted) ?? []
  return (
    <>
      <div className="space-y-1.5">
        <Label>{t('automations.inspector.closureReason', 'Reason')}</Label>
        <Select
          value={typeof ac.closure_reason === 'string' ? ac.closure_reason : ''}
          onValueChange={(v) => onChange({ ...ac, closure_reason: v })}
          disabled={disabled}
        >
          <SelectTrigger aria-label={t('automations.inspector.closureReason', 'Reason')}>
            <SelectValue placeholder={t('automations.inspector.chooseReason', 'Choose a reason')} />
          </SelectTrigger>
          <SelectContent>
            {reasons.map((r) => (
              <SelectItem key={r} value={r}>
                {closureReasonLabel(t, r)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="automation-justification">
          {t('automations.inspector.justification', 'Justification (required)')}
        </Label>
        <Textarea
          id="automation-justification"
          rows={3}
          disabled={disabled}
          defaultValue={typeof ac.justification === 'string' ? ac.justification : ''}
          onBlur={(e) => onChange({ ...ac, justification: e.target.value.trim() })}
        />
      </div>
      {type === 'request_risk_acceptance' && (
        <div className="space-y-1.5">
          <Label htmlFor="automation-expires">
            {t('automations.inspector.expiresInDays', 'Expires after (days, 1 to 365)')}
          </Label>
          <Input
            id="automation-expires"
            type="number"
            min={1}
            max={365}
            disabled={disabled}
            defaultValue={typeof ac.expires_in_days === 'number' ? ac.expires_in_days : ''}
            onBlur={(e) => {
              const n = Math.round(Number(e.target.value))
              onChange({
                ...ac,
                expires_in_days: Number.isFinite(n) && n > 0 ? Math.min(365, n) : undefined,
              })
            }}
          />
        </div>
      )}
    </>
  )
}

function ActionFields({
  config,
  catalog,
  readOnly,
  onChange,
}: {
  config: WorkflowNodeConfig
  catalog?: WorkflowCatalog
  readOnly?: boolean
  onChange: (c: WorkflowNodeConfig) => void
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const type = config.action_type
  const ac = config.action_config ?? {}
  const removed = removedTypeOf(catalog, 'action', config)
  const setAc = (next: Record<string, unknown>) => onChange({ ...config, action_config: next })
  return (
    <>
      <CatalogTypeSelect
        label={t('automations.inspector.action', 'Action')}
        placeholder={t('automations.inspector.chooseAction', 'Choose an action')}
        entries={catalogEntriesFor(catalog, 'action')}
        value={type}
        removed={removed}
        name={labels.action}
        disabled={readOnly}
        onChange={(v) => onChange({ ...config, action_type: v, action_config: {} })}
      />
      {removed ? null : type === 'trigger_scan' ? (
        <SavedScanSelect
          value={typeof ac.scan_id === 'string' ? ac.scan_id : undefined}
          onChange={(id) => setAc({ ...ac, scan_id: id })}
        />
      ) : type === 'add_tags' || type === 'remove_tags' ? (
        <div className="space-y-1.5">
          <Label htmlFor="automation-tags">
            {t('automations.inspector.tags', 'Tags (comma separated)')}
          </Label>
          <Input
            id="automation-tags"
            disabled={readOnly}
            defaultValue={Array.isArray(ac.tags) ? (ac.tags as string[]).join(', ') : ''}
            onBlur={(e) => setAc({ ...ac, tags: parseTags(e.target.value) })}
          />
        </div>
      ) : type === 'update_status' ? (
        <div className="space-y-1.5">
          <Label>{t('automations.inspector.statusTarget', 'Set the status to')}</Label>
          <Select
            value={typeof ac.status === 'string' ? ac.status : ''}
            onValueChange={(v) => setAc({ ...ac, status: v })}
            disabled={readOnly}
          >
            <SelectTrigger
              aria-label={t('automations.inspector.statusTarget', 'Set the status to')}
            >
              <SelectValue
                placeholder={t('automations.inspector.chooseStatus', 'Choose a status')}
              />
            </SelectTrigger>
            <SelectContent>
              {AUTOMATION_STATUS_TARGETS.map((s) => (
                <SelectItem key={s} value={s}>
                  {s === 'confirmed'
                    ? t('automations.inspector.statusConfirmed', 'Confirmed')
                    : t('automations.inspector.statusInProgress', 'In progress')}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            {t(
              'automations.inspector.statusHint',
              'An automation may only set Confirmed or In progress. Closing a finding goes through a request a person decides.'
            )}
          </p>
        </div>
      ) : type === 'request_false_positive' || type === 'request_risk_acceptance' ? (
        <>
          <p className="rounded-md border bg-muted/40 p-2 text-xs" data-testid="request-note">
            {t('automations.inspector.requestNote', 'Creates a request; a person decides.')}
          </p>
          <RequestFields type={type} ac={ac} disabled={readOnly} onChange={setAc} />
        </>
      ) : type ? (
        <JsonField
          key={type}
          id="automation-action-config"
          label={t('automations.inspector.settingsJson', 'Settings (JSON)')}
          value={config.action_config}
          onChange={(v) => setAc(v)}
        />
      ) : null}
    </>
  )
}

/**
 * The Automations canvas inspector: name and the selected step's settings.
 * Type pickers list only what the catalog returns; the API validates the
 * saved draft and refuses a type it does not run.
 */
export function AutomationInspector({
  node,
  catalog,
  readOnly = false,
  onChange,
  onDelete,
}: {
  node: AutomationNode
  catalog?: WorkflowCatalog
  readOnly?: boolean
  onChange: (data: AutomationNodeData) => void
  onDelete: () => void
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const { data } = node
  const config = data.config
  const [label, setLabel] = useState(data.label)
  useEffect(() => setLabel(data.label), [node.id, data.label])
  const setConfig = (c: WorkflowNodeConfig) => onChange({ ...data, config: c })
  const triggerRemoved = removedTypeOf(catalog, 'trigger', config)
  const notificationRemoved = removedTypeOf(catalog, 'notification', config)

  return (
    <div className="space-y-4" data-testid="automation-inspector">
      <div className="space-y-1.5">
        <Label htmlFor="automation-node-name">{t('automations.inspector.name', 'Name')}</Label>
        <Input
          id="automation-node-name"
          value={label}
          disabled={readOnly}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={() => onChange({ ...data, label: label.trim() || data.nodeKey })}
        />
        <p className="font-mono text-xs text-muted-foreground">{data.nodeKey}</p>
      </div>

      {node.type === 'trigger' && (
        <>
          <CatalogTypeSelect
            label={t('automations.inspector.trigger', 'Trigger')}
            placeholder={t('automations.inspector.chooseTrigger', 'Choose a trigger')}
            entries={catalogEntriesFor(catalog, 'trigger')}
            value={config.trigger_type}
            removed={triggerRemoved}
            name={labels.trigger}
            disabled={readOnly}
            onChange={(v) => setConfig({ ...config, trigger_type: v })}
          />
          {config.trigger_type && config.trigger_type !== 'manual' && !triggerRemoved && (
            <JsonField
              key={`${node.id}-trigger`}
              id="automation-trigger-config"
              label={t('automations.inspector.filter', 'Filter (JSON, optional)')}
              value={config.trigger_config as Record<string, unknown> | undefined}
              onChange={(v) => setConfig({ ...config, trigger_config: v })}
            />
          )}
        </>
      )}

      {node.type === 'condition' && (
        <div className="space-y-1.5">
          <Label htmlFor="automation-condition">
            {t('automations.inspector.condition', 'Condition')}
          </Label>
          <Input
            id="automation-condition"
            className="font-mono text-xs"
            placeholder="finding.severity == 'critical'"
            defaultValue={config.condition_expr ?? ''}
            disabled={readOnly}
            key={node.id}
            onBlur={(e) => setConfig({ ...config, condition_expr: e.target.value })}
          />
          <p className="text-xs text-muted-foreground">
            {t(
              'automations.inspector.conditionHint',
              'Connect the Yes and No handles to what runs in each case.'
            )}
          </p>
        </div>
      )}

      {node.type === 'action' && (
        <ActionFields
          key={node.id}
          config={config}
          catalog={catalog}
          readOnly={readOnly}
          onChange={setConfig}
        />
      )}

      {node.type === 'notification' && (
        <>
          <CatalogTypeSelect
            label={t('automations.inspector.channel', 'Channel')}
            placeholder={t('automations.inspector.chooseChannel', 'Choose a channel')}
            entries={catalogEntriesFor(catalog, 'notification')}
            value={config.notification_type}
            removed={notificationRemoved}
            name={labels.notification}
            disabled={readOnly}
            onChange={(v) => setConfig({ ...config, notification_type: v })}
          />
          {!notificationRemoved && (
            <JsonField
              key={`${node.id}-notify`}
              id="automation-notification-config"
              label={t('automations.inspector.settingsJson', 'Settings (JSON)')}
              value={config.notification_config}
              onChange={(v) => setConfig({ ...config, notification_config: v })}
            />
          )}
        </>
      )}

      {!readOnly && (
        <Button variant="outline" size="sm" className="text-destructive" onClick={onDelete}>
          <Trash2 className="me-2 h-4 w-4" />
          {t('automations.inspector.removeNode', 'Remove node')}
        </Button>
      )}
    </div>
  )
}
