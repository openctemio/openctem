'use client'

/**
 * Inbound webhook of one Jira integration: the URL to paste into Jira's
 * webhook form, and its secret. The secret is stored encrypted and never
 * shown again after it is generated: the administrator copies it once (or
 * enters the one Jira generated).
 */

import { useState } from 'react'
import { Copy, KeyRound } from 'lucide-react'
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
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'

import {
  useJiraWebhookApi,
  useRotateJiraWebhookSecretApi,
  useSetJiraWebhookSecretApi,
} from '../api/use-integrations-api'
import type { Integration } from '../types/integration.types'

const MIN_SECRET_LENGTH = 16

/** The absolute URL Jira must call: the console's origin plus the path. */
export function absoluteWebhookUrl(path: string, origin: string): string {
  return origin.replace(/\/+$/, '') + path
}

function CopyField({ value, label }: { value: string; label: string }) {
  const { t } = useTranslation()
  return (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1.5 font-mono text-xs">
        {value}
      </code>
      <Button
        type="button"
        variant="outline"
        size="icon"
        className="h-8 w-8 shrink-0"
        aria-label={label}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value)
            toast.success(t('settings.jiraWebhook.copied', 'Copied'))
          } catch {
            toast.error(t('settings.jiraWebhook.copyFailed', 'Could not copy'))
          }
        }}
      >
        <Copy className="h-3.5 w-3.5" />
      </Button>
    </div>
  )
}

export function JiraWebhookDialog({
  integration,
  open,
  onOpenChange,
}: {
  integration: Integration
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { data, isLoading, mutate } = useJiraWebhookApi(open ? integration.id : null)
  const { trigger: rotate, isMutating: rotating } = useRotateJiraWebhookSecretApi(integration.id)
  const { trigger: setSecret, isMutating: saving } = useSetJiraWebhookSecretApi(integration.id)
  const [shownSecret, setShownSecret] = useState('')
  const [entered, setEntered] = useState('')

  const origin = typeof window === 'undefined' ? '' : window.location.origin
  const url = data ? absoluteWebhookUrl(data.webhook_url, origin) : ''

  async function handleRotate() {
    try {
      const res = await rotate()
      setShownSecret(res?.webhook_secret ?? '')
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('settings.jiraWebhook.rotateFailed', 'Could not generate a secret'))
      )
    }
  }

  async function handleSave() {
    try {
      await setSecret({ secret: entered.trim() })
      setEntered('')
      setShownSecret('')
      toast.success(t('settings.jiraWebhook.saved', 'Secret saved'))
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('settings.jiraWebhook.saveFailed', 'Could not save the secret'))
      )
    }
  }

  const enteredValid = entered.trim().length >= MIN_SECRET_LENGTH && !/\s/.test(entered.trim())

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setShownSecret('')
          setEntered('')
        }
        onOpenChange(next)
      }}
    >
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {t('settings.jiraWebhook.title', 'Inbound webhook: {name}', { name: integration.name })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.jiraWebhook.description',
              'Create a webhook in Jira (System > WebHooks) with this URL and secret, for issue updated events. Jira signs each delivery with the secret; deliveries without a valid signature are refused.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          {isLoading || !data ? (
            <Skeleton className="h-24 w-full" />
          ) : (
            <>
              <div className="space-y-1.5">
                <Label>{t('settings.jiraWebhook.url', 'Webhook URL')}</Label>
                <CopyField
                  value={url}
                  label={t('settings.jiraWebhook.copyUrl', 'Copy the webhook URL')}
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <Label>{t('settings.jiraWebhook.secret', 'Secret')}</Label>
                  {data.has_secret ? (
                    <Badge variant="secondary">{t('settings.jiraWebhook.secretSet', 'Set')}</Badge>
                  ) : (
                    <Badge variant="outline">
                      {t('settings.jiraWebhook.secretNotSet', 'Not set')}
                    </Badge>
                  )}
                </div>
                {shownSecret ? (
                  <div className="space-y-1.5">
                    <CopyField
                      value={shownSecret}
                      label={t('settings.jiraWebhook.copySecret', 'Copy the secret')}
                    />
                    <p className="text-xs text-amber-600 dark:text-amber-400">
                      {t(
                        'settings.jiraWebhook.shownOnce',
                        'Copy it now and paste it into Jira. It is not shown again.'
                      )}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    {data.has_secret
                      ? t(
                          'settings.jiraWebhook.hiddenHint',
                          'The secret is stored encrypted and never shown again. Generate a new one, or enter the one from Jira, to replace it; the old one stops working at once.'
                        )
                      : t(
                          'settings.jiraWebhook.noneHint',
                          'No secret yet: every delivery is refused until one is set.'
                        )}
                  </p>
                )}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => void handleRotate()}
                  disabled={rotating}
                >
                  <KeyRound className="mr-2 h-3.5 w-3.5" />
                  {data.has_secret
                    ? t('settings.jiraWebhook.rotate', 'Generate a new secret')
                    : t('settings.jiraWebhook.generate', 'Generate a secret')}
                </Button>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="jira-webhook-secret">
                  {t('settings.jiraWebhook.enterLabel', 'Or enter the secret from Jira')}
                </Label>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <Input
                    id="jira-webhook-secret"
                    type="password"
                    autoComplete="off"
                    value={entered}
                    onChange={(e) => setEntered(e.target.value)}
                    placeholder={t(
                      'settings.jiraWebhook.enterPlaceholder',
                      'At least 16 characters, no spaces'
                    )}
                  />
                  <Button
                    type="button"
                    onClick={() => void handleSave()}
                    disabled={!enteredValid || saving}
                  >
                    {t('settings.jiraWebhook.save', 'Save secret')}
                  </Button>
                </div>
              </div>
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('settings.jiraWebhook.close', 'Close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
