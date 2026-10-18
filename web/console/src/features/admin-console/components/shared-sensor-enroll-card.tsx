'use client'

/**
 * System > Platform scanning: enroll a shared sensor (RFC-100 §7). A super
 * admin issues a single-use instance enrollment token with a reason and an
 * authenticator code; it is valid 5 to 60 minutes and shown once. The sensor
 * is started with SENSOR_INSTANCE_ENROLLMENT_TOKEN, pairs with its own key and
 * becomes a shared sensor (no organization, least-privilege grant).
 */

import { useId, useState } from 'react'
import { Check, Copy, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { SharedSensorEnrollmentToken } from '../api/use-scan-policy'
import { StepUpCodeHint, stepUpCodeReady, useStepUpCodeOptional } from './step-up-code-hint'
import { RoleRequiredNotice } from './role-required-notice'

export const SHARED_SENSOR_TOKEN_ENV = 'SENSOR_INSTANCE_ENROLLMENT_TOKEN'

export interface SharedSensorEnrollCardProps {
  canEdit: boolean
  onIssue: (input: {
    name: string
    ttlMinutes: number
    reason: string
    code: string
  }) => Promise<SharedSensorEnrollmentToken>
}

export function SharedSensorEnrollCard({ canEdit, onIssue }: SharedSensorEnrollCardProps) {
  const { t } = useTranslation()
  const id = useId()
  const [name, setName] = useState('')
  const [ttl, setTtl] = useState(60)
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const codeOptional = useStepUpCodeOptional()
  const [codeError, setCodeError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [issued, setIssued] = useState<SharedSensorEnrollmentToken | null>(null)
  const [copied, setCopied] = useState(false)

  const ttlValid = Number.isInteger(ttl) && ttl >= 5 && ttl <= 60

  const issue = async () => {
    setBusy(true)
    setCodeError(null)
    try {
      const out = await onIssue({
        name: name.trim(),
        ttlMinutes: ttl,
        reason: reason.trim(),
        code: code.trim(),
      })
      setIssued(out)
      setCopied(false)
      setOpen(false)
      setReason('')
      setCode('')
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setOpen(false)
      toast.error(e instanceof Error ? e.message : t('admin.sharedSensorEnroll.issueFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.sharedSensorEnroll.title')}</CardTitle>
          <CardDescription>{t('admin.sharedSensorEnroll.desc')}</CardDescription>
          <CardDescription>{t('admin.sharedSensorEnroll.mintRightBefore')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {issued ? (
            <div className="space-y-2 rounded-md border p-3">
              <p className="text-sm font-medium">{t('admin.sharedSensorEnroll.shownOnce')}</p>
              <div className="flex min-w-0 items-center gap-2">
                <code className="min-w-0 flex-1 rounded bg-muted px-2 py-1.5 text-xs break-all select-all">
                  {`${SHARED_SENSOR_TOKEN_ENV}=${issued.token}`}
                </code>
                <Button
                  type="button"
                  size="icon"
                  variant="outline"
                  aria-label={t('admin.sharedSensorEnroll.copy')}
                  onClick={async () => {
                    if (await copyToClipboard(issued.token)) setCopied(true)
                  }}
                >
                  {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                </Button>
              </div>
              <p className="text-sm text-muted-foreground">
                {t('admin.sharedSensorEnroll.expires', undefined, {
                  time: new Date(issued.expires_at).toLocaleString(),
                })}
              </p>
              <div className="flex justify-end">
                <Button variant="outline" onClick={() => setIssued(null)}>
                  {t('admin.sharedSensorEnroll.done')}
                </Button>
              </div>
            </div>
          ) : canEdit ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor={`${id}-name`}>{t('admin.sharedSensorEnroll.name')}</Label>
                <Input
                  id={`${id}-name`}
                  value={name}
                  maxLength={128}
                  placeholder={t('admin.sharedSensorEnroll.namePlaceholder')}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor={`${id}-ttl`}>{t('admin.sharedSensorEnroll.ttl')}</Label>
                <Input
                  id={`${id}-ttl`}
                  type="number"
                  min={5}
                  max={60}
                  value={ttl}
                  aria-invalid={!ttlValid}
                  onChange={(e) => setTtl(Number(e.target.value))}
                />
              </div>
              <div className="flex justify-end sm:col-span-2">
                <Button onClick={() => setOpen(true)} disabled={!ttlValid || busy}>
                  {t('admin.sharedSensorEnroll.issue')}
                </Button>
              </div>
            </div>
          ) : (
            <RoleRequiredNotice needed="super_admin" />
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={open}
        onOpenChange={(o) => {
          if (!busy) setOpen(o)
        }}
        title={t('admin.sharedSensorEnroll.confirmTitle')}
        desc={<p>{t('admin.sharedSensorEnroll.confirmDesc')}</p>}
        disabled={!stepUpCodeReady(code, codeOptional) || !reason.trim()}
        isLoading={busy}
        handleConfirm={() => void issue()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('admin.sharedSensorEnroll.issuing')}
            </>
          ) : (
            t('admin.sharedSensorEnroll.issue')
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
