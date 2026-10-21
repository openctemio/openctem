'use client'

/**
 * "Create issues automatically when…" for one Jira integration: the minimum
 * severity, the minimum priority class (either one is enough), KEV always,
 * and a daily cap. It applies to automatic creates (workflows); a person can
 * still create an issue for any finding after confirming. Findings held back
 * are re-checked when they change and created then.
 */

import { useState } from 'react'
import { toast } from 'sonner'

import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { useSeverityLabel } from '@/hooks/use-scale-labels'

import {
  MAX_DAILY_CAP,
  previewTicketCreatePolicy,
  saveTicketCreatePolicy,
  useTicketCreatePolicy,
  type TicketCreatePolicy,
  type TicketCreatePolicyPreview,
} from '../api/use-ticket-create-policy'
import type { Integration } from '../types/integration.types'

const CLASSES = ['P0', 'P1', 'P2', 'P3'] as const
const NO_CLASS = 'none'

export function TicketCreatePolicyDialog({
  integration,
  open,
  onOpenChange,
}: {
  integration: Integration
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { data, isLoading, error } = useTicketCreatePolicy(integration.id, open)
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('ticketPolicy.title', 'When to create issues')}</DialogTitle>
          <DialogDescription>
            {t(
              'ticketPolicy.description',
              'Which findings automations file as issues on {name}. People can still create an issue for any finding after confirming.',
              { name: integration.name }
            )}
          </DialogDescription>
        </DialogHeader>
        {isLoading || !data ? (
          <DialogBody>
            {error ? (
              <p className="text-destructive text-sm">
                {getErrorMessage(error, t('ticketPolicy.loadFailed', 'Could not load the policy'))}
              </p>
            ) : (
              <Skeleton className="h-48 w-full" />
            )}
          </DialogBody>
        ) : (
          <PolicyForm
            integrationId={integration.id}
            initial={data.policy}
            held={data.stats.held_by_reason}
            createdToday={data.stats.created_today}
            onDone={() => onOpenChange(false)}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function PolicyForm({
  integrationId,
  initial,
  held,
  createdToday,
  onDone,
}: {
  integrationId: string
  initial: TicketCreatePolicy
  held: Partial<Record<string, number>>
  createdToday: number
  onDone: () => void
}) {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  const [policy, setPolicy] = useState<TicketCreatePolicy>(initial)
  const [capText, setCapText] = useState(String(initial.daily_cap))
  const [preview, setPreview] = useState<TicketCreatePolicyPreview | null>(null)
  const [busy, setBusy] = useState<'preview' | 'save' | null>(null)

  const cap = Number(capText)
  const capValid = /^\d+$/.test(capText.trim()) && cap >= 0 && cap <= MAX_DAILY_CAP
  const current: TicketCreatePolicy = { ...policy, daily_cap: capValid ? cap : 0 }

  const update = (p: Partial<TicketCreatePolicy>) => {
    setPolicy((prev) => ({ ...prev, ...p }))
    setPreview(null)
  }

  const runPreview = async () => {
    setBusy('preview')
    try {
      setPreview(await previewTicketCreatePolicy(integrationId, current))
    } catch (err) {
      toast.error(getErrorMessage(err, t('ticketPolicy.previewFailed', 'Could not preview')))
    } finally {
      setBusy(null)
    }
  }

  const save = async () => {
    setBusy('save')
    try {
      await saveTicketCreatePolicy(integrationId, current)
      toast.success(t('ticketPolicy.saved', 'Policy saved'))
      onDone()
    } catch (err) {
      toast.error(getErrorMessage(err, t('ticketPolicy.saveFailed', 'Could not save the policy')))
    } finally {
      setBusy(null)
    }
  }

  const heldBelow = held.below_threshold ?? 0
  const heldCap = held.daily_cap ?? 0
  const heldFailed = held.create_failed ?? 0

  return (
    <>
      <DialogBody>
        <div className="grid gap-4">
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="tcp-severity">
                {t('ticketPolicy.minSeverity', 'Severity at least')}
              </Label>
              <Select
                value={policy.min_severity}
                onValueChange={(v) =>
                  update({ min_severity: v as TicketCreatePolicy['min_severity'] })
                }
              >
                <SelectTrigger id="tcp-severity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITY_LEVELS.map((s) => (
                    <SelectItem key={s} value={s}>
                      {severityLabel(s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tcp-class">
                {t('ticketPolicy.minPriorityClass', 'Or priority class at least')}
              </Label>
              <Select
                value={policy.min_priority_class || NO_CLASS}
                onValueChange={(v) =>
                  update({
                    min_priority_class: (v === NO_CLASS
                      ? ''
                      : v) as TicketCreatePolicy['min_priority_class'],
                  })
                }
              >
                <SelectTrigger id="tcp-class">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NO_CLASS}>{t('ticketPolicy.noClass', 'Not used')}</SelectItem>
                  {CLASSES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex items-start justify-between gap-4">
            <div className="grid gap-1">
              <Label htmlFor="tcp-kev">
                {t('ticketPolicy.alwaysKev', 'Always for known exploited (KEV)')}
              </Label>
              <p className="text-muted-foreground text-xs">
                {t(
                  'ticketPolicy.alwaysKevHint',
                  'A finding in the KEV catalog gets an issue whatever its severity.'
                )}
              </p>
            </div>
            <Switch
              id="tcp-kev"
              checked={policy.always_kev}
              onCheckedChange={(v) => update({ always_kev: v })}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="tcp-cap">{t('ticketPolicy.dailyCap', 'Daily limit')}</Label>
            <Input
              id="tcp-cap"
              inputMode="numeric"
              value={capText}
              aria-invalid={!capValid}
              onChange={(e) => {
                setCapText(e.target.value)
                setPreview(null)
              }}
            />
            <p className={capValid ? 'text-muted-foreground text-xs' : 'text-destructive text-xs'}>
              {capValid
                ? t(
                    'ticketPolicy.dailyCapHint',
                    'Most issues automations may create per day (UTC); 0 means no limit. The rest wait for the next day, most severe first.'
                  )
                : t('ticketPolicy.dailyCapInvalid', 'Enter a whole number from 0 to {max}.', {
                    max: MAX_DAILY_CAP,
                  })}
            </p>
          </div>

          <div className="flex flex-wrap gap-2 text-xs">
            <Badge variant="secondary">
              {t('ticketPolicy.createdToday', 'Created today: {n}', { n: createdToday })}
            </Badge>
            <Badge variant="outline">
              {t('ticketPolicy.heldBelow', 'Below the policy: {n}', { n: heldBelow })}
            </Badge>
            {heldCap > 0 && (
              <Badge variant="outline">
                {t('ticketPolicy.heldCap', 'Waiting for the daily limit: {n}', { n: heldCap })}
              </Badge>
            )}
            {heldFailed > 0 && (
              <Badge variant="destructive">
                {t('ticketPolicy.heldFailed', 'Create failed: {n}', { n: heldFailed })}
              </Badge>
            )}
          </div>

          {preview && (
            <div className="bg-muted/50 rounded-md border p-3 text-sm" role="status">
              <p>
                {t(
                  'ticketPolicy.previewLast30',
                  'Of {total} findings first seen in the last 30 days, {pass} would get an issue.',
                  { total: preview.last_30_days_total, pass: preview.last_30_days_pass }
                )}
              </p>
              <p>
                {t(
                  'ticketPolicy.previewHeld',
                  'Of {held} findings held now, {release} would be created after saving.',
                  { held: preview.held_now, release: preview.held_would_pass }
                )}
              </p>
            </div>
          )}
          <p className="text-muted-foreground text-xs">
            {t(
              'ticketPolicy.notSecurity',
              'This only reduces noise. Sharing limits (TLP) still apply to every issue.'
            )}
          </p>
        </div>
      </DialogBody>
      <DialogFooter>
        <Button variant="outline" onClick={runPreview} disabled={!capValid || busy !== null}>
          {busy === 'preview'
            ? t('ticketPolicy.previewing', 'Counting…')
            : t('ticketPolicy.preview', 'Preview')}
        </Button>
        <Button onClick={save} disabled={!capValid || busy !== null}>
          {busy === 'save' ? t('ticketPolicy.saving', 'Saving…') : t('ticketPolicy.save', 'Save')}
        </Button>
      </DialogFooter>
    </>
  )
}
