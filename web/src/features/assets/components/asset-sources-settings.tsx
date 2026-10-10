'use client'

/**
 * Settings › Asset sources (RFC-069 §12): which source decides asset values,
 * as a ranked list per attribute class plus a default list the classes
 * inherit. Each row has its TTL, a trust switch and when it last reported.
 * A preview shows what the edited order would change before it is saved.
 * Demoting a connector asks the person to re-authenticate (shared client).
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Eye, Loader2, RotateCcw, Save } from 'lucide-react'
import { toast } from 'sonner'
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
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSection } from '@/features/shared'
import { get } from '@/lib/api/client'
import {
  ATTRIBUTE_LABEL,
  clonePolicy,
  displayValue,
  policyValid,
  ruleParts,
  type AttributeClass,
  type PolicyPreview,
  type ReconciliationSettings,
  type SourcePolicy,
  type SourceRule,
} from '../lib/attribute-sources'
import { SourceRankList, useRuleLabel } from './source-rank-list'

export interface AssetSourcesSettingsFormProps {
  settings: ReconciliationSettings
  canEdit: boolean
  onSave: (p: SourcePolicy) => Promise<void>
  onPreview: (p: SourcePolicy, assetId?: string) => Promise<PolicyPreview>
}

/** Adds a source the organization has as its own row, above its kind's row. */
function AddSourceRow({
  rules,
  settings,
  onAdd,
}: {
  rules: SourceRule[]
  settings: ReconciliationSettings
  onAdd: (rules: SourceRule[]) => void
}) {
  const { t } = useTranslation()
  const label = useRuleLabel()
  const listed = new Set(rules.map((r) => r.source))
  const candidates = settings.sources
    .filter((s) => s.name)
    .map((s) => `${s.kind}:${s.name}`)
    .filter((src) => !listed.has(src))
  if (candidates.length === 0) return null
  return (
    <Select
      value=""
      onValueChange={(src) => {
        const { kind } = ruleParts(src)
        const at = rules.findIndex((r) => r.source === kind)
        const base = rules[at]
        const row: SourceRule = { source: src, ttl_days: base?.ttl_days ?? 30, trusted: true }
        const next = [...rules]
        next.splice(at < 0 ? next.length : at, 0, row)
        onAdd(next)
      }}
    >
      <SelectTrigger
        className="mt-2 h-8 w-full sm:w-72"
        aria-label={t('assetSources.addSource', 'Rank a source separately')}
      >
        <SelectValue placeholder={t('assetSources.addSource', 'Rank a source separately')} />
      </SelectTrigger>
      <SelectContent>
        {candidates.map((src) => (
          <SelectItem key={src} value={src}>
            {label(src)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

interface AssetHit {
  id: string
  name: string
}

/** Picks one asset by name for the preview. */
function AssetPicker({ onPick }: { onPick: (a: AssetHit | null) => void }) {
  const { t } = useTranslation()
  const [q, setQ] = useState('')
  const [hits, setHits] = useState<AssetHit[]>([])
  useEffect(() => {
    const term = q.trim()
    if (term.length < 2) {
      setHits([])
      return
    }
    let live = true
    const timer = setTimeout(() => {
      get<{ data?: AssetHit[] }>(`/api/v1/assets?search=${encodeURIComponent(term)}&per_page=8`)
        .then((res) => {
          if (live) setHits(res?.data ?? [])
        })
        .catch(() => {
          if (live) setHits([])
        })
    }, 250)
    return () => {
      live = false
      clearTimeout(timer)
    }
  }, [q])
  return (
    <div className="space-y-1">
      <Input
        className="h-8 w-full sm:w-72"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder={t('assetSources.preview.searchAsset', 'Search an asset by name')}
        aria-label={t('assetSources.preview.searchAsset', 'Search an asset by name')}
      />
      {hits.length > 0 && (
        <ul className="max-w-72 rounded-md border text-sm" role="listbox">
          {hits.map((h) => (
            <li key={h.id}>
              <button
                type="button"
                className="w-full px-2 py-1 text-start hover:bg-muted"
                onClick={() => {
                  onPick(h)
                  setQ(h.name)
                  setHits([])
                }}
              >
                {h.name}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function PreviewPanel({
  draft,
  onPreview,
}: {
  draft: SourcePolicy
  onPreview: AssetSourcesSettingsFormProps['onPreview']
}) {
  const { t } = useTranslation()
  const [mode, setMode] = useState<'sample' | 'asset'>('sample')
  const [asset, setAsset] = useState<AssetHit | null>(null)
  const [result, setResult] = useState<PolicyPreview | null>(null)
  const [busy, setBusy] = useState(false)
  // A preview of an older draft is not shown as current.
  useEffect(() => setResult(null), [draft])

  const run = async () => {
    setBusy(true)
    try {
      setResult(await onPreview(draft, mode === 'asset' ? asset?.id : undefined))
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : t('assetSources.preview.failed', 'Preview failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <SettingsSection
      title={t('assetSources.preview.title', 'Preview')}
      description={t(
        'assetSources.preview.description',
        'See which values would change under the order above before you save it.'
      )}
    >
      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <Label htmlFor="preview-mode">{t('assetSources.preview.on', 'Preview on')}</Label>
          <Select value={mode} onValueChange={(v) => setMode(v as 'sample' | 'asset')}>
            <SelectTrigger id="preview-mode" className="h-8 w-56">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="sample">
                {t('assetSources.preview.sample', 'Assets with sources (sample)')}
              </SelectItem>
              <SelectItem value="asset">
                {t('assetSources.preview.oneAsset', 'One asset')}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
        {mode === 'asset' && <AssetPicker onPick={setAsset} />}
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={run}
          disabled={busy || (mode === 'asset' && !asset) || !policyValid(draft)}
        >
          {busy ? (
            <Loader2 className="me-1 h-4 w-4 animate-spin" />
          ) : (
            <Eye className="me-1 h-4 w-4" />
          )}
          {t('assetSources.preview.run', 'Preview')}
        </Button>
      </div>
      {result && (
        <div className="space-y-2" data-testid="preview-result">
          <p className="text-sm">
            {t(
              'assetSources.preview.summary',
              '{assets} of {scanned} assets would change ({values} values). {conflicts} conflicts.',
              {
                assets: result.changed_assets,
                scanned: result.scanned_assets,
                values: result.changed_values,
                conflicts: result.conflicts,
              }
            )}
          </p>
          {result.truncated && (
            <p className="text-xs text-muted-foreground">
              {t('assetSources.preview.truncated', 'Only the first 5000 assets were checked.')}
            </p>
          )}
          {result.samples.length > 0 && (
            <ul className="divide-y rounded-md border text-sm">
              {result.samples.map((s) => (
                <li
                  key={`${s.asset_id}-${s.attribute}`}
                  className="flex flex-wrap items-center gap-2 px-2 py-1.5"
                >
                  <span className="font-medium">{s.asset_name}</span>
                  <span className="text-muted-foreground">
                    {t(`assetSources.attribute.${s.attribute}`, ATTRIBUTE_LABEL[s.attribute])}
                  </span>
                  <span>
                    {displayValue(s.current)} → {displayValue(s.next)}
                  </span>
                  <Badge variant="outline">{s.next_source}</Badge>
                  {s.conflict && (
                    <Badge variant="outline" className="border-warning text-warning">
                      {t('assetSources.conflict', 'Sources disagree')}
                    </Badge>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </SettingsSection>
  )
}

export function AssetSourcesSettingsForm({
  settings,
  canEdit,
  onSave,
  onPreview,
}: AssetSourcesSettingsFormProps) {
  const { t } = useTranslation()
  const initial = useMemo(() => clonePolicy(settings.effective), [settings])
  const [draft, setDraft] = useState<SourcePolicy>(initial)
  const [saving, setSaving] = useState(false)
  useEffect(() => setDraft(initial), [initial])

  const dirty = useMemo(() => JSON.stringify(draft) !== JSON.stringify(initial), [draft, initial])
  const valid = policyValid(draft)

  const classLabel = useCallback((c: AttributeClass) => t(`assetSources.class.${c}`, c), [t])
  const setDefault = useCallback(
    (rules: SourceRule[]) => setDraft((d) => ({ ...d, default: rules })),
    []
  )
  const setClass = useCallback(
    (c: AttributeClass, rules: SourceRule[] | undefined) =>
      setDraft((d) => {
        const classes = { ...d.classes }
        if (rules) classes[c] = rules
        else delete classes[c]
        return { ...d, classes }
      }),
    []
  )

  const submit = async () => {
    setSaving(true)
    try {
      await onSave(draft)
      toast.success(t('assetSources.saved', 'Asset source settings saved'))
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : t('assetSources.saveFailed', 'Could not save the settings')
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-8">
      <SettingsSection
        title={t('assetSources.default.title', 'Default for all attributes')}
        description={t(
          'assetSources.default.description',
          'The most trusted source first. Among sources in the same row the one that saw the asset last wins. A source that is switched off, or has no row, never decides. Classes use this list unless customised.'
        )}
      >
        <SourceRankList
          label={t('assetSources.default.list', 'Default source order')}
          scopeLabel={t('assetSources.default.scope', 'any attribute')}
          rules={draft.default}
          sources={settings.sources}
          canEdit={canEdit}
          onChange={setDefault}
        />
        {canEdit && <AddSourceRow rules={draft.default} settings={settings} onAdd={setDefault} />}
      </SettingsSection>

      {settings.classes.map(({ class: c, attributes }) => {
        const own = draft.classes[c]
        const label = classLabel(c)
        return (
          <SettingsSection
            key={c}
            title={label}
            description={
              attributes.length > 0
                ? t('assetSources.appliesTo', 'Applies to: {attributes}', {
                    attributes: attributes
                      .map((a) => t(`assetSources.attribute.${a}`, ATTRIBUTE_LABEL[a]))
                      .join(', '),
                  })
                : t('assetSources.noAttributesYet', 'No attribute uses this class yet.')
            }
            actions={
              canEdit && own ? (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setClass(c, undefined)}
                >
                  <RotateCcw className="me-1 h-3.5 w-3.5" />
                  {t('assetSources.reset', 'Reset to default')}
                </Button>
              ) : undefined
            }
          >
            <div className="flex items-center gap-2">
              <Switch
                id={`customise-${c}`}
                checked={!!own}
                disabled={!canEdit}
                onCheckedChange={(on) =>
                  setClass(c, on ? draft.default.map((r) => ({ ...r })) : undefined)
                }
              />
              <Label htmlFor={`customise-${c}`} className="font-normal">
                {t('assetSources.customise', 'Customise for this class')}
              </Label>
            </div>
            {own ? (
              <>
                <SourceRankList
                  label={t('assetSources.classList', '{class} source order', { class: label })}
                  scopeLabel={label}
                  rules={own}
                  sources={settings.sources}
                  canEdit={canEdit}
                  onChange={(rules) => setClass(c, rules)}
                />
                {canEdit && (
                  <AddSourceRow rules={own} settings={settings} onAdd={(r) => setClass(c, r)} />
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">
                {t('assetSources.inherits', 'Uses the default order.')}
              </p>
            )}
          </SettingsSection>
        )
      })}

      {!valid && (
        <p className="text-sm text-destructive" role="alert">
          {t(
            'assetSources.ttlInvalid',
            'Each time limit must be a whole number of days, 0 to 3650.'
          )}
        </p>
      )}

      {canEdit && <PreviewPanel draft={draft} onPreview={onPreview} />}

      {canEdit && (
        <div className="flex items-center gap-3">
          <Button onClick={submit} disabled={saving || !valid || !dirty}>
            {saving ? (
              <Loader2 className="me-1 h-4 w-4 animate-spin" />
            ) : (
              <Save className="me-1 h-4 w-4" />
            )}
            {t('assetSources.save', 'Save changes')}
          </Button>
          <p className="text-xs text-muted-foreground">
            {t(
              'assetSources.saveHint',
              'Moving a connector down asks you to confirm your identity. Values on assets update in the background; changes appear in each asset’s timeline.'
            )}
          </p>
        </div>
      )}
    </div>
  )
}
