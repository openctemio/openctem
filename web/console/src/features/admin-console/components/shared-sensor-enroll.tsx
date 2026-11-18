'use client'

/**
 * Platform sensors > Enroll a sensor (RFC-100 §7): an action in the page's
 * title row. A super admin issues a single-use instance enrollment token with
 * a reason and an authenticator code; it is valid 5 to 60 minutes and shown
 * once. The sensor is started with SENSOR_INSTANCE_ENROLLMENT_TOKEN, pairs
 * with its own key and becomes a shared sensor (no organization,
 * least-privilege grant).
 *
 * Two dialogs: the form (name, validity, the reason and the code), then the
 * token, shown once.
 */

import { useState } from 'react'
import { Check, Copy, Plus } from 'lucide-react'
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
import type { SharedSensorEnrollmentToken } from '../api/use-scan-policy'
import { AdminConfirmDialog } from './admin-confirm-dialog'
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
  const [formOpen, setFormOpen] = useState(false)
  const [name, setName] = useState('')
  const [ttl, setTtl] = useState(60)
  const [issued, setIssued] = useState<SharedSensorEnrollmentToken | null>(null)
  const [copied, setCopied] = useState(false)

  const ttlValid = Number.isInteger(ttl) && ttl >= 5 && ttl <= 60

  const openForm = () => {
    setName('')
    setTtl(60)
    setFormOpen(true)
  }

  const description = (
    <>
      {t('admin.sharedSensorEnroll.desc')} {t('admin.sharedSensorEnroll.mintRightBefore')}
    </>
  )

  return (
    <>
      <Button onClick={openForm} data-testid="sensors-enroll">
        <Plus aria-hidden />
        {t('admin.sharedSensorEnroll.action')}
      </Button>

      {canEdit ? (
        // One dialog, as for every privileged console action: the sensor's
        // name and lifetime, then the reason and a fresh code (the API
        // refuses the token without both). A refused code keeps it open.
        <AdminConfirmDialog
          open={formOpen}
          onOpenChange={setFormOpen}
          title={t('admin.sharedSensorEnroll.title')}
          description={description}
          confirmLabel={t('admin.sharedSensorEnroll.issue')}
          reasonPlaceholder={t(
            'admin.sharedSensorEnroll.reasonPlaceholder',
            'Second scanner for the Hanoi region, change 2231'
          )}
          requireCode
          canSubmit={ttlValid}
          onConfirm={async ({ reason, totp_code }) => {
            const out = await onIssue({
              name: name.trim(),
              ttlMinutes: ttl,
              reason,
              code: (totp_code ?? '').trim(),
            })
            setIssued(out)
            setCopied(false)
          }}
        >
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
        </AdminConfirmDialog>
      ) : (
        <FormDialog
          open={formOpen}
          onOpenChange={setFormOpen}
          title={t('admin.sharedSensorEnroll.title')}
          description={description}
          submitLabel={t('admin.sharedSensorEnroll.issue')}
          canSubmit={false}
          onSubmit={() => undefined}
          data-testid="sensors-enroll-dialog"
        >
          <RoleRequiredNotice needed="super_admin" />
        </FormDialog>
      )}

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
                <code className="min-w-0 flex-1 rounded bg-muted px-2 py-1.5 text-code break-all select-all">
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
              <p className="text-body text-muted-foreground">
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
