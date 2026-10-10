'use client'

import * as React from 'react'
import { toast } from 'sonner'
import { useSWRConfig } from 'swr'

import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { TagInput } from '@/components/ui/tag-input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { SettingsSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'

import { updateVulnMatchingSettings, VULN_MATCHING_SETTINGS_ENDPOINT } from '../api'
import {
  DEFAULT_MIN_CONFIDENCE,
  DEFAULT_MIN_SEVERITY,
  MAX_MUTED_PRODUCTS,
  MIN_SEVERITY_OPTIONS,
  NVD_ATTRIBUTION,
  validateVulnMatching,
  type VulnMatchingSettings,
} from '../types'

/** What the page header needs to render the form's Save action. */
export interface VulnMatchingFormStatus {
  dirty: boolean
  submitting: boolean
}

interface VulnMatchingSettingsFormProps {
  initial: VulnMatchingSettings
  /** The section's ETag from the organization settings read (If-Match). */
  etag?: string
  /** Called after a save or a conflict, to re-read the settings and their ETags. */
  onSaved?: () => void
  formId: string
  onStatusChange?: (status: VulnMatchingFormStatus) => void
}

interface FormState {
  enabled: boolean
  min_confidence: string
  min_severity: string
  include_distro_builds: boolean
  internet_facing_only: boolean
  muted_products: string[]
}

function toFormState(s: VulnMatchingSettings): FormState {
  return {
    enabled: s.enabled ?? false,
    min_confidence: s.min_confidence ? String(s.min_confidence) : '',
    min_severity: s.min_severity || DEFAULT_MIN_SEVERITY,
    include_distro_builds: s.include_distro_builds ?? false,
    internet_facing_only: s.internet_facing_only ?? false,
    muted_products: s.muted_products ?? [],
  }
}

/** The payload; an empty confidence means the default (sent as 0). */
export function toVulnMatchingPayload(f: FormState): VulnMatchingSettings {
  const conf = f.min_confidence.trim()
  return {
    enabled: f.enabled,
    min_confidence: conf === '' ? 0 : Number(conf),
    min_severity: f.min_severity === DEFAULT_MIN_SEVERITY ? '' : f.min_severity,
    include_distro_builds: f.include_distro_builds,
    internet_facing_only: f.internet_facing_only,
    muted_products: f.muted_products.map((p) => p.trim()).filter(Boolean),
  }
}

function isConflict(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === 'SETTINGS_CONFLICT'
}

export function VulnMatchingSettingsForm({
  initial,
  etag,
  onSaved,
  formId,
  onStatusChange,
}: VulnMatchingSettingsFormProps) {
  const { mutate } = useSWRConfig()
  const [form, setForm] = React.useState<FormState>(() => toFormState(initial))
  const [baseline, setBaseline] = React.useState<FormState>(() => toFormState(initial))
  const [submitting, setSubmitting] = React.useState(false)

  const dirty = JSON.stringify(form) !== JSON.stringify(baseline)
  React.useEffect(() => {
    onStatusChange?.({ dirty, submitting })
  }, [dirty, submitting, onStatusChange])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload = toVulnMatchingPayload(form)
    const err = validateVulnMatching({
      min_confidence: form.min_confidence.trim() === '' ? null : Number(form.min_confidence),
      muted_products: payload.muted_products,
    })
    if (err) {
      toast.error(err)
      return
    }
    try {
      setSubmitting(true)
      const saved = await updateVulnMatchingSettings(payload, etag)
      toast.success('Vulnerability matching settings saved')
      setForm(toFormState(saved))
      setBaseline(toFormState(saved))
      void mutate(VULN_MATCHING_SETTINGS_ENDPOINT, saved, false)
      onSaved?.()
    } catch (e2) {
      if (isConflict(e2)) {
        toast.error(
          'Someone else changed these settings since you opened the page. Reload to see their change.'
        )
        onSaved?.()
      } else {
        toast.error(getErrorMessage(e2))
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form id={formId} className="space-y-8" onSubmit={handleSubmit} noValidate>
      <SettingsSection
        title="Matching"
        description="Compare the software your assets run with published CVEs and open findings for the versions they affect. Matching runs when software changes and when new CVEs arrive."
      >
        <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
          <div>
            <Label htmlFor="vm-enabled">Create findings from version matches</Label>
            <p className="text-sm text-muted-foreground">
              Off: matches stay visible on each asset&apos;s Software tab, no finding is opened.
            </p>
          </div>
          <Switch
            id="vm-enabled"
            checked={form.enabled}
            onCheckedChange={(checked) => setForm((s) => ({ ...s, enabled: checked }))}
          />
        </div>
      </SettingsSection>

      <SettingsSection
        title="Which matches become findings"
        description="A version read from a banner is evidence, not proof: below 80 a match is potential and stays at P2 or lower unless the CVE is known exploited."
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="vm-confidence">Minimum confidence</Label>
            <Input
              id="vm-confidence"
              inputMode="numeric"
              placeholder={String(DEFAULT_MIN_CONFIDENCE)}
              value={form.min_confidence}
              onChange={(e) => setForm((s) => ({ ...s, min_confidence: e.target.value }))}
              aria-describedby="vm-confidence-help"
            />
            <p id="vm-confidence-help" className="text-xs text-muted-foreground">
              0 to 100. Empty means {DEFAULT_MIN_CONFIDENCE}.
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vm-severity">Minimum severity</Label>
            <Select
              value={form.min_severity}
              onValueChange={(v) => setForm((s) => ({ ...s, min_severity: v }))}
            >
              <SelectTrigger id="vm-severity" aria-describedby="vm-severity-help">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {MIN_SEVERITY_OPTIONS.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p id="vm-severity-help" className="text-xs text-muted-foreground">
              A CVE in the KEV catalog or with an EPSS score of 0.1 or more always passes.
            </p>
          </div>
        </div>
        <div className="space-y-3">
          <ToggleRow
            id="vm-distro"
            label="Include distribution builds"
            description="Versions like 8.2p1 Ubuntu-4ubuntu0.5: the distribution often back-ports fixes without changing the upstream version, so these matches are often wrong."
            checked={form.include_distro_builds}
            onChange={(v) => setForm((s) => ({ ...s, include_distro_builds: v }))}
          />
          <ToggleRow
            id="vm-internet"
            label="Internet-facing assets only"
            description="Leave off to cover internal assets too."
            checked={form.internet_facing_only}
            onChange={(v) => setForm((s) => ({ ...s, internet_facing_only: v }))}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="vm-muted">Muted products</Label>
          <TagInput
            value={form.muted_products}
            onChange={(tags) => setForm((s) => ({ ...s, muted_products: tags }))}
            placeholder="Product name, e.g. OpenSSH"
            maxTags={MAX_MUTED_PRODUCTS}
          />
          <p className="text-xs text-muted-foreground">
            Never opened as findings, for products you patch another way. At most{' '}
            {MAX_MUTED_PRODUCTS}.
          </p>
        </div>
      </SettingsSection>

      <p className="text-xs text-muted-foreground">{NVD_ATTRIBUTION}</p>
    </form>
  )
}

function ToggleRow({
  id,
  label,
  description,
  checked,
  onChange,
}: {
  id: string
  label: string
  description: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
      <div>
        <Label htmlFor={id}>{label}</Label>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  )
}
