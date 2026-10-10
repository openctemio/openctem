'use client'

/**
 * The owner-only scope setting (RFC-054 §12.4): how long an intrusive (T2)
 * scope entry may last. 7, 30 (default), 90 or 365 days, or permanent. A T2
 * entry still needs a verified domain and an approval. Saving asks for a
 * reason and step-up re-authentication, is audited and tells every
 * administrator. Everyone else sees the value read-only.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2, Save } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
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
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSection } from '@/features/shared'
import { usePermissions } from '@/lib/permissions'
import { updateScopeIntrusiveSettings } from '../api/use-scope-api'
import type { ApiScopeSettings, ScopeT2MaxDuration } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'

export const T2_DURATION_LABEL: Record<ScopeT2MaxDuration, string> = {
  '7d': '7 days',
  '30d': '30 days (default)',
  '90d': '90 days',
  '365d': '365 days',
  permanent: 'Permanent',
}

export function ScopeIntrusiveSettings({
  settings,
  onSaved,
}: {
  settings: ApiScopeSettings
  onSaved?: (s: ApiScopeSettings) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const { isOwner } = usePermissions()
  const owner = isOwner()
  const current = (settings.t2_max_duration as ScopeT2MaxDuration) || '30d'
  const currentDays = settings.t2_attestation_days ?? 90
  const [value, setValue] = useState<ScopeT2MaxDuration>(current)
  const [days, setDays] = useState(currentDays)
  const [reason, setReason] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => setValue(current), [current])
  useEffect(() => setDays(currentDays), [currentDays])
  const clampedDays = Math.min(180, Math.max(30, Math.round(days) || 90))
  const dirty = value !== current || clampedDays !== currentDays

  const save = async () => {
    setSaving(true)
    try {
      const out = await updateScopeIntrusiveSettings({
        t2_max_duration: value,
        t2_attestation_days: clampedDays,
        reason: reason.trim(),
      })
      setReason('')
      if (out) onSaved?.(out)
      toast.success('Intrusive entry limit saved', {
        description: 'Every administrator was notified.',
      })
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'Could not save the setting.'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <SettingsSection
      title="Intrusive (T2) entries"
      description={
        owner
          ? 'Only an owner changes this. Saving asks for a reason and for you to confirm your identity; it is audited and every administrator is told.'
          : 'Set by an owner of your organization.'
      }
      actions={
        owner ? (
          <Button
            size="sm"
            onClick={() => void save()}
            disabled={saving || !dirty || !reason.trim()}
          >
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save
          </Button>
        ) : undefined
      }
    >
      <Card>
        <CardContent className="space-y-4 py-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
            <div className="min-w-0 sm:max-w-md">
              <Label htmlFor={`${id}-t2`} className="text-sm font-medium">
                Longest intrusive entry
              </Label>
              <p className="mt-1 text-sm text-muted-foreground text-pretty">
                How long an entry that allows intrusive (T2) probes may last. Every T2 entry still
                needs a verified domain and an approval. Long and permanent T2 entries are confirmed
                again periodically, or they fall back to non-intrusive (T1).
              </p>
            </div>
            <Select
              value={value}
              onValueChange={(v) => setValue(v as ScopeT2MaxDuration)}
              disabled={!owner || saving}
            >
              <SelectTrigger id={`${id}-t2`} className="w-full shrink-0 sm:w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(T2_DURATION_LABEL) as ScopeT2MaxDuration[]).map((k) => (
                  <SelectItem key={k} value={k}>
                    {T2_DURATION_LABEL[k]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
            <div className="min-w-0 sm:max-w-md">
              <Label htmlFor={`${id}-attest`} className="text-sm font-medium">
                Confirm long T2 entries every
              </Label>
              <p className="mt-1 text-sm text-muted-foreground text-pretty">
                30 to 180 days. When a confirmation is due, owners and administrators are asked
                &quot;Keep T2?&quot;. Without an answer within 14 days the entry falls back to
                non-intrusive (T1); it is never removed.
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Input
                id={`${id}-attest`}
                type="number"
                min={30}
                max={180}
                className="w-24"
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                disabled={!owner || saving}
              />
              <span className="text-sm text-muted-foreground">days</span>
            </div>
          </div>
          {owner && dirty && (
            <div className="space-y-2">
              <Label htmlFor={`${id}-reason`}>Reason</Label>
              <Textarea
                id={`${id}-reason`}
                rows={2}
                maxLength={1000}
                value={reason}
                placeholder="For example: standing pentest contract, ticket SEC-42."
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
          )}
        </CardContent>
      </Card>
    </SettingsSection>
  )
}
