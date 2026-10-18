'use client'

/**
 * Requests > Sign-ups: the burst alert thresholds. When sign-ups of one kind
 * from one network (/24, /48) or one email domain reach a threshold within
 * the window, every administrator is emailed once and a high entry is
 * written to the admin audit log. 0 turns a dimension off; ignored domains
 * skip the per-domain count. A change needs a super admin, a reason and a
 * fresh authenticator code; it is audited.
 */

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { SignupAlertThresholds } from '../api/use-signup-events'
import { StepUpCodeHint, stepUpCodeReady, useStepUpCodeOptional } from './step-up-code-hint'

const MAX_THRESHOLD = 100_000
const MIN_WINDOW = 5
const MAX_WINDOW = 1440
const MAX_IGNORED = 50

const NUMBER_FIELDS = [
  ['per_ip_prefix', 'perPrefix', 0, MAX_THRESHOLD],
  ['per_email_domain', 'perDomain', 0, MAX_THRESHOLD],
  ['window_minutes', 'window', MIN_WINDOW, MAX_WINDOW],
] as const

/** One domain per line or comma; lower-cased, de-duplicated. */
export function parseDomains(text: string): string[] {
  const seen = new Set<string>()
  for (const raw of text.split(/[\s,]+/)) {
    const d = raw.trim().toLowerCase().replace(/^@/, '').replace(/\.$/, '')
    if (d) seen.add(d)
  }
  return [...seen].sort()
}

export interface SignupAlertsFormProps {
  thresholds: SignupAlertThresholds
  canEdit: boolean
  onSave: (next: SignupAlertThresholds, reason: string, code: string) => Promise<void>
}

export function SignupAlertsForm({ thresholds, canEdit, onSave }: SignupAlertsFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [value, setValue] = useState(thresholds)
  const [domains, setDomains] = useState(thresholds.ignored_domains.join('\n'))
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const codeOptional = useStepUpCodeOptional()
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setValue(thresholds)
    setDomains(thresholds.ignored_domains.join('\n'))
  }, [thresholds])

  const ignored = parseDomains(domains)
  const next: SignupAlertThresholds = { ...value, ignored_domains: ignored }
  const dirty =
    NUMBER_FIELDS.some(([key]) => value[key] !== thresholds[key]) ||
    ignored.join(',') !== [...thresholds.ignored_domains].sort().join(',')
  const valid =
    NUMBER_FIELDS.every(
      ([key, , min, max]) => Number.isInteger(value[key]) && value[key] >= min && value[key] <= max
    ) && ignored.length <= MAX_IGNORED

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      await onSave(next, reason.trim(), code.trim())
      setOpen(false)
      setReason('')
      setCode('')
      toast.success(t('admin.signupAlerts.saved'))
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setOpen(false)
      toast.error(e instanceof Error ? e.message : t('admin.signupAlerts.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.signupAlerts.title')}</CardTitle>
          <CardDescription>{t('admin.signupAlerts.desc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-3">
            {NUMBER_FIELDS.map(([key, label, min, max]) => (
              <div key={key} className="space-y-2">
                <Label htmlFor={`${id}-${key}`}>{t(`admin.signupAlerts.${label}`)}</Label>
                <Input
                  id={`${id}-${key}`}
                  type="number"
                  inputMode="numeric"
                  min={min}
                  max={max}
                  step={1}
                  value={Number.isNaN(value[key]) ? '' : value[key]}
                  onChange={(e) => setValue({ ...value, [key]: e.target.valueAsNumber })}
                  disabled={!canEdit || busy}
                />
              </div>
            ))}
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-ignored`}>{t('admin.signupAlerts.ignored')}</Label>
            <Textarea
              id={`${id}-ignored`}
              rows={3}
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              disabled={!canEdit || busy}
              placeholder={t('admin.signupAlerts.ignoredPlaceholder')}
            />
            <p className="text-sm text-muted-foreground">{t('admin.signupAlerts.ignoredHint')}</p>
          </div>
          <p className="text-sm text-muted-foreground">{t('admin.signupAlerts.zeroOff')}</p>
          {canEdit ? (
            <div className="flex justify-end">
              <Button onClick={() => setOpen(true)} disabled={!dirty || !valid || busy}>
                {t('admin.scanPolicy.save')}
              </Button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t('admin.scanPolicy.superOnly')}</p>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          if (!busy) setOpen(o)
        }}
        title={t('admin.signupAlerts.confirmTitle')}
        desc={<p>{t('admin.signupAlerts.confirmDesc')}</p>}
        disabled={!stepUpCodeReady(code, codeOptional) || !reason.trim()}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.scanPolicy.saving')}
            </>
          ) : (
            t('admin.scanPolicy.confirm')
          )
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={`${id}-reason`}>{t('admin.scanPolicy.reason')}</Label>
            <Textarea
              id={`${id}-reason`}
              rows={2}
              maxLength={1000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-code`}>{t('admin.scanPolicy.code')}</Label>
            <Input
              id={`${id}-code`}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={8}
              aria-invalid={!!codeError}
            />
            <StepUpCodeHint optional={codeOptional} />
            {codeError && <p className="text-sm text-destructive">{codeError}</p>}
          </div>
        </div>
      </ConfirmDialog>
    </>
  )
}
