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
  WORKFLOW_ACTION_TYPES,
  WORKFLOW_NOTIFICATION_TYPES,
  WORKFLOW_TRIGGER_TYPES,
  type WorkflowActionType,
  type WorkflowNodeConfig,
  type WorkflowNotificationType,
  type WorkflowTriggerType,
} from '@/lib/api/workflow-types'
import type { AutomationNode, AutomationNodeData } from '../lib/automation-graph'
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

function ActionFields({
  config,
  onChange,
}: {
  config: WorkflowNodeConfig
  onChange: (c: WorkflowNodeConfig) => void
}) {
  const { t } = useTranslation()
  const labels = useAutomationLabels()
  const type = config.action_type
  const ac = config.action_config ?? {}
  const unsupported = type !== undefined && !WORKFLOW_ACTION_TYPES.includes(type as never)
  return (
    <>
      <div className="space-y-1.5">
        <Label>{t('automations.inspector.action', 'Action')}</Label>
        <Select
          value={unsupported ? '' : (type ?? '')}
          onValueChange={(v) =>
            onChange({ ...config, action_type: v as WorkflowActionType, action_config: {} })
          }
        >
          <SelectTrigger aria-label={t('automations.inspector.action', 'Action')}>
            <SelectValue
              placeholder={t('automations.inspector.chooseAction', 'Choose an action')}
            />
          </SelectTrigger>
          <SelectContent>
            {WORKFLOW_ACTION_TYPES.map((a) => (
              <SelectItem key={a} value={a}>
                {labels.action(a)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {unsupported && (
          <p className="text-xs text-warning">
            {t(
              'automations.inspector.actionUnsupported',
              '{label} is not supported. Choose another action before saving.',
              { label: labels.action(type) }
            )}
          </p>
        )}
      </div>
      {type === 'trigger_scan' ? (
        <SavedScanSelect
          value={typeof ac.scan_id === 'string' ? ac.scan_id : undefined}
          onChange={(id) => onChange({ ...config, action_config: { ...ac, scan_id: id } })}
        />
      ) : type === 'add_tags' || type === 'remove_tags' ? (
        <div className="space-y-1.5">
          <Label htmlFor="automation-tags">
            {t('automations.inspector.tags', 'Tags (comma separated)')}
          </Label>
          <Input
            id="automation-tags"
            defaultValue={Array.isArray(ac.tags) ? (ac.tags as string[]).join(', ') : ''}
            onBlur={(e) =>
              onChange({ ...config, action_config: { ...ac, tags: parseTags(e.target.value) } })
            }
          />
        </div>
      ) : type && !unsupported ? (
        <JsonField
          key={type}
          id="automation-action-config"
          label={t('automations.inspector.settingsJson', 'Settings (JSON)')}
          value={config.action_config}
          onChange={(v) => onChange({ ...config, action_config: v })}
        />
      ) : null}
    </>
  )
}

/**
 * The Automations canvas inspector: name, description and the selected
 * node's settings, bound to the trigger, action and notification types the
 * platform runs. The API validates the saved workflow.
 */
export function AutomationInspector({
  node,
  onChange,
  onDelete,
}: {
  node: AutomationNode
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
  const triggerUnsupported =
    config.trigger_type !== undefined &&
    !WORKFLOW_TRIGGER_TYPES.includes(config.trigger_type as never)

  return (
    <div className="space-y-4" data-testid="automation-inspector">
      <div className="space-y-1.5">
        <Label htmlFor="automation-node-name">{t('automations.inspector.name', 'Name')}</Label>
        <Input
          id="automation-node-name"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={() => onChange({ ...data, label: label.trim() || data.nodeKey })}
        />
      </div>

      {node.type === 'trigger' && (
        <>
          <div className="space-y-1.5">
            <Label>{t('automations.inspector.trigger', 'Trigger')}</Label>
            <Select
              value={triggerUnsupported ? '' : (config.trigger_type ?? '')}
              onValueChange={(v) =>
                setConfig({ ...config, trigger_type: v as WorkflowTriggerType })
              }
            >
              <SelectTrigger aria-label={t('automations.inspector.trigger', 'Trigger')}>
                <SelectValue
                  placeholder={t('automations.inspector.chooseTrigger', 'Choose a trigger')}
                />
              </SelectTrigger>
              <SelectContent>
                {WORKFLOW_TRIGGER_TYPES.map((k) => (
                  <SelectItem key={k} value={k}>
                    {labels.trigger(k)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {triggerUnsupported && config.trigger_type && (
              <p className="text-xs text-warning">
                {t(
                  'automations.inspector.triggerNeverFires',
                  '{label} never fires. Choose another trigger before saving.',
                  { label: labels.trigger(config.trigger_type) }
                )}
              </p>
            )}
          </div>
          {config.trigger_type && config.trigger_type !== 'manual' && (
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
        <ActionFields key={node.id} config={config} onChange={setConfig} />
      )}

      {node.type === 'notification' && (
        <>
          <div className="space-y-1.5">
            <Label>{t('automations.inspector.channel', 'Channel')}</Label>
            <Select
              value={config.notification_type ?? ''}
              onValueChange={(v) =>
                setConfig({ ...config, notification_type: v as WorkflowNotificationType })
              }
            >
              <SelectTrigger aria-label={t('automations.inspector.channel', 'Channel')}>
                <SelectValue
                  placeholder={t('automations.inspector.chooseChannel', 'Choose a channel')}
                />
              </SelectTrigger>
              <SelectContent>
                {WORKFLOW_NOTIFICATION_TYPES.map((k) => (
                  <SelectItem key={k} value={k}>
                    {labels.notification(k)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <JsonField
            key={`${node.id}-notify`}
            id="automation-notification-config"
            label={t('automations.inspector.settingsJson', 'Settings (JSON)')}
            value={config.notification_config}
            onChange={(v) => setConfig({ ...config, notification_config: v })}
          />
        </>
      )}

      <Button variant="outline" size="sm" className="text-destructive" onClick={onDelete}>
        <Trash2 className="me-2 h-4 w-4" />
        {t('automations.inspector.removeNode', 'Remove node')}
      </Button>
    </div>
  )
}
