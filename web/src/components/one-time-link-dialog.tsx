'use client'

import { useState } from 'react'
import { Check, Copy, ShieldAlert } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'

interface OneTimeLinkDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  /** What the link is and who it is for. */
  description: string
  /** The full link; a bearer secret. It lives in this component's props only. */
  link: string
  /** RFC3339: when the link stops working. */
  expiresAt?: string
}

function formatExpiry(iso?: string): string | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/**
 * A link an administrator hands over (invitation, password reset). It is a
 * bearer secret the API returns once and does not keep: this dialog shows it
 * with a copy button and says so. Closing it drops the link.
 */
export function OneTimeLinkDialog({
  open,
  onOpenChange,
  title,
  description,
  link,
  expiresAt,
}: OneTimeLinkDialogProps) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const expiry = formatExpiry(expiresAt)

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setCopied(false)
        onOpenChange(next)
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-3 py-2">
            <div className="flex min-w-0 items-center gap-2">
              <code
                className="bg-muted min-w-0 flex-1 rounded px-2 py-1.5 font-mono text-xs break-all select-all"
                data-testid="one-time-link"
              >
                {link}
              </code>
              <Button
                type="button"
                size="icon"
                variant="outline"
                aria-label={t('common.oneTimeLink.copy', 'Copy link')}
                onClick={async () => {
                  if (await copyToClipboard(link)) setCopied(true)
                }}
              >
                {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
              </Button>
            </div>
            <Alert className="border-warning/40 bg-warning/10">
              <ShieldAlert className="text-warning size-4" />
              <AlertTitle>{t('common.oneTimeLink.shownOnce', 'Shown once')}</AlertTitle>
              <AlertDescription>
                <p>
                  {t(
                    'common.oneTimeLink.handOver',
                    'Give this link to the person over a channel you trust. Anyone who opens it can use it.'
                  )}
                </p>
                <p>
                  {expiry
                    ? t(
                        'common.oneTimeLink.expires',
                        'It expires {expiry}. It will not be shown again; copy a new link if it is lost.',
                        { expiry }
                      )
                    : t(
                        'common.oneTimeLink.notShownAgain',
                        'It will not be shown again; copy a new link if it is lost.'
                      )}
                </p>
              </AlertDescription>
            </Alert>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>
            {t('common.oneTimeLink.done', 'Done')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
