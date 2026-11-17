'use client'

/**
 * Platform sensors > Enroll a sensor (RFC-100 §7): an action in the page's
 * title row. A super admin issues a single-use instance enrollment token with
 * a reason and an authenticator code; it is valid 5 to 60 minutes and shown
 * once. The sensor is started with SENSOR_INSTANCE_ENROLLMENT_TOKEN, pairs
 * with its own key and becomes a shared sensor (no organization,
 * least-privilege grant).
 *
 * Three steps, each a dialog: the form (name, validity), the confirmation
 * with the reason and the code on top of it, then the token, shown once.
 */

import { useId, useState } from 'react'
import { Check, Copy, Loader2, Plus } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { FormDialog, FormField, FormStack } from '@/features/shared/components/forms'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { SharedSensorEnrollmentToken } from '../api/use-scan-policy'
import { ReasonAndCodeFields, useReasonAndCode } from './step-up-code-hint'
import { RoleRequiredNotice } from './role-required-notice'

export const SHARED_SENSOR_TOKEN_ENV = 'SENSOR_INSTANCE_ENROLLMENT_TOKEN'

export interface SharedSensorEnrollProps {
  canEdit: boolean
  onIssue: (input: {
    name: string
    ttlMinutes: number
    reason: string
    code: string
  }) => Promise<SharedSensorEnrollmentToken>
}

export function SharedSensorEnroll({ canEdit, onIssue }: SharedSensorEnrollProps) {
  const { t } = useTranslation()
  const id = useId()
  const [formOpen, setFormOpen] = useState(false)
  const [name, setName] = useState('')
  const [ttl, setTtl] = useState(60)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const rc = useReasonAndCode(confirmOpen)
  const [busy, setBusy] = useState(false)
  const [issued, setIssued] = useState<SharedSensorEnrollmentToken | null>(null)
  const [copied, setCopied] = useState(false)

  const ttlValid = Number.isInteger(ttl) && ttl >= 5 && ttl <= 60

  const openForm = () => {
    setName('')
    setTtl(60)
    setFormOpen(true)
  }

  const issue = async () => {
    setBusy(true)
    rc.setCodeError(null)
    try {
      const out = await onIssue({
        name: name.trim(),
        ttlMinutes: ttl,
        reason: rc.reason.trim(),
        code: rc.code.trim(),
      })
      setIssued(out)
      setCopied(false)
      setConfirmOpen(false)
      setFormOpen(false)
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        rc.refuseCode(e.message)
        return
      }
      setConfirmOpen(false)
      toast.error(e instanceof Error ? e.message : t('admin.sharedSensorEnroll.issueFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button onClick={openForm} data-testid="sensors-enroll">
        <Plus aria-hidden />
        {t('admin.sharedSensorEnroll.action')}
      </Button>

      <FormDialog
        open={formOpen}
        onOpenChange={(o) => {
          if (!busy) setFormOpen(o)
        }}
        title={t('admin.sharedSensorEnroll.title')}
        description={
          <>
            {t('admin.sharedSensorEnroll.desc')} {t('admin.sharedSensorEnroll.mintRightBefore')}
          </>
        }
        submitLabel={t('admin.sharedSensorEnroll.issue')}
        canSubmit={canEdit && ttlValid && !busy}
        onSubmit={() => setConfirmOpen(true)}
        dirty={name.trim() !== '' || ttl !== 60}
        data-testid="sensors-enroll-dialog"
      >
        {canEdit ? (
          <FormStack>
            <FormField label={t('admin.sharedSensorEnroll.name')} required={false}>
              <Input
                value={name}
                maxLength={128}
                placeholder={t('admin.sharedSensorEnroll.namePlaceholder')}
                onChange={(e) => setName(e.target.value)}
              />
            </FormField>
            <FormField label={t('admin.sharedSensorEnroll.ttl')}>
              {(control) => (
                <Input
                  {...control}
                  type="number"
                  min={5}
                  max={60}
                  value={ttl}
                  aria-invalid={!ttlValid || undefined}
                  onChange={(e) => setTtl(Number(e.target.value))}
                />
              )}
            </FormField>
          </FormStack>
        ) : (
          <RoleRequiredNotice needed="super_admin" />
        )}
      </FormDialog>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(o) => {
          if (!busy) setConfirmOpen(o)
        }}
        title={t('admin.sharedSensorEnroll.confirmTitle')}
        desc={<p>{t('admin.sharedSensorEnroll.confirmDesc')}</p>}
        disabled={!rc.codeOk || !rc.reasonOk}
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
        <ReasonAndCodeFields id={id} state={rc} />
      </ConfirmDialog>

      <Dialog
        open={issued !== null}
        onOpenChange={(o) => {
          if (!o) setIssued(null)
        }}
      >
        <DialogContent size="md" data-testid="sensors-enroll-token">
          <DialogHeader>
            <DialogTitle className="text-dialog">{t('admin.sharedSensorEnroll.title')}</DialogTitle>
            <DialogDescription>{t('admin.sharedSensorEnroll.shownOnce')}</DialogDescription>
          </DialogHeader>
          {issued && (
            <DialogBody className="space-y-2">
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
            </DialogBody>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIssued(null)}>
              {t('admin.sharedSensorEnroll.done')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
