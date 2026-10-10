'use client'

/**
 * Settings › Asset sources (RFC-069): per attribute, which kinds of source
 * the organization trusts and in what order, and how long a source's value
 * counts after it last reported it. A person's lock always wins and is not
 * listed.
 */

import { useEffect, useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Loader2, Save } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { SettingsSection } from '@/features/shared'
import {
  ATTRIBUTE_LABEL,
  RANKABLE_KINDS,
  SOURCE_KIND_LABEL,
  TRACKED_ATTRIBUTES,
  move,
  trustedKinds,
  type ReconciliationPolicy,
  type ReconciliationSettings,
  type TrackedAttribute,
} from '../lib/attribute-sources'

const MAX_TTL_DAYS = 3650

/** The editable form of a policy: trusted kinds in order, then the untrusted ones. */
function toDraft(p: ReconciliationPolicy) {
  const order: Record<string, string[]> = {}
  const trusted: Record<string, Set<string>> = {}
  for (const attr of TRACKED_ATTRIBUTES) {
    const t = trustedKinds(p, attr)
    order[attr] = [...t, ...RANKABLE_KINDS.filter((k) => !t.includes(k))]
    trusted[attr] = new Set(t)
  }
  return { order, trusted, ttl: { ...p.ttl_days } }
}

export function AssetSourcesSettingsForm({
  settings,
  canEdit,
  onSave,
}: {
  settings: ReconciliationSettings
  canEdit: boolean
  onSave: (p: ReconciliationPolicy) => Promise<void>
}) {
  const initial = useMemo(() => toDraft(settings.effective), [settings])
  const [draft, setDraft] = useState(initial)
  const [saving, setSaving] = useState(false)
  useEffect(() => setDraft(initial), [initial])

  const ttlInvalid = RANKABLE_KINDS.some((k) => {
    const v = draft.ttl[k]
    return !Number.isInteger(v) || v < 0 || v > MAX_TTL_DAYS
  })

  const reorder = (attr: TrackedAttribute, i: number, delta: number) =>
    setDraft((d) => ({ ...d, order: { ...d.order, [attr]: move(d.order[attr], i, delta) } }))
  const toggle = (attr: TrackedAttribute, kind: string, on: boolean) =>
    setDraft((d) => {
      const next = new Set(d.trusted[attr])
      if (on) next.add(kind)
      else next.delete(kind)
      return { ...d, trusted: { ...d.trusted, [attr]: next } }
    })

  const submit = async () => {
    const precedence: Record<string, string[]> = {}
    for (const attr of TRACKED_ATTRIBUTES) {
      precedence[attr] = draft.order[attr].filter((k) => draft.trusted[attr].has(k))
    }
    setSaving(true)
    try {
      await onSave({ precedence, ttl_days: draft.ttl })
      toast.success('Asset source settings saved')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not save the settings')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-8">
      <SettingsSection
        title="Which source decides"
        description="For each attribute, the kinds of source trusted to set it, most trusted first. Among equally trusted sources the one that saw the asset last wins. A value a person set and locked on the asset page always wins."
      >
        <div className="grid gap-4 md:grid-cols-2">
          {TRACKED_ATTRIBUTES.map((attr) => (
            <fieldset key={attr} className="rounded-lg border p-3">
              <legend className="px-1 text-sm font-medium">{ATTRIBUTE_LABEL[attr]}</legend>
              <ol className="space-y-1.5" aria-label={`${ATTRIBUTE_LABEL[attr]} precedence`}>
                {draft.order[attr].map((kind, i) => {
                  const id = `trust-${attr}-${kind}`
                  return (
                    <li key={kind} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        id={id}
                        checked={draft.trusted[attr].has(kind)}
                        disabled={!canEdit}
                        onCheckedChange={(v) => toggle(attr, kind, v === true)}
                      />
                      <Label htmlFor={id} className="flex-1 font-normal">
                        {SOURCE_KIND_LABEL[kind as keyof typeof SOURCE_KIND_LABEL]}
                        {!draft.trusted[attr].has(kind) && (
                          <span className="ms-2 text-xs text-muted-foreground">not trusted</span>
                        )}
                      </Label>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7"
                        disabled={!canEdit || i === 0}
                        aria-label={`Move ${SOURCE_KIND_LABEL[kind as keyof typeof SOURCE_KIND_LABEL]} up for ${ATTRIBUTE_LABEL[attr]}`}
                        onClick={() => reorder(attr, i, -1)}
                      >
                        <ArrowUp className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7"
                        disabled={!canEdit || i === draft.order[attr].length - 1}
                        aria-label={`Move ${SOURCE_KIND_LABEL[kind as keyof typeof SOURCE_KIND_LABEL]} down for ${ATTRIBUTE_LABEL[attr]}`}
                        onClick={() => reorder(attr, i, 1)}
                      >
                        <ArrowDown className="h-3.5 w-3.5" />
                      </Button>
                    </li>
                  )
                })}
              </ol>
            </fieldset>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          A scan is any sensor or CI report, whatever it says about itself. By default scans are not
          trusted for criticality, owner or data classification.
        </p>
      </SettingsSection>

      <SettingsSection
        title="How long a value counts"
        description="Days after a source last reported a value before it stops counting. The value stays on the asset until a current source reports another one. 0 means it never goes stale."
      >
        <div className="flex flex-wrap gap-4">
          {RANKABLE_KINDS.map((k) => (
            <div key={k} className="space-y-1">
              <Label htmlFor={`ttl-${k}`}>{SOURCE_KIND_LABEL[k]}</Label>
              <Input
                id={`ttl-${k}`}
                type="number"
                min={0}
                max={MAX_TTL_DAYS}
                className="w-28"
                disabled={!canEdit}
                value={Number.isFinite(draft.ttl[k]) ? draft.ttl[k] : ''}
                onChange={(e) =>
                  setDraft((d) => ({
                    ...d,
                    ttl: { ...d.ttl, [k]: e.target.value === '' ? NaN : Number(e.target.value) },
                  }))
                }
              />
            </div>
          ))}
        </div>
        {ttlInvalid && (
          <p className="text-xs text-destructive">
            Each value must be a whole number of days, 0 to {MAX_TTL_DAYS}.
          </p>
        )}
      </SettingsSection>

      {canEdit && (
        <Button onClick={submit} disabled={saving || ttlInvalid}>
          {saving ? (
            <Loader2 className="me-1 h-4 w-4 animate-spin" />
          ) : (
            <Save className="me-1 h-4 w-4" />
          )}
          Save changes
        </Button>
      )}
    </div>
  )
}
