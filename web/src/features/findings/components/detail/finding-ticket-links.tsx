'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { toast } from 'sonner'
import { ExternalLink, Link2, Unlink } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { get, post, del } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { sanitizeExternalUrl } from '@/lib/utils'
import { useCanCreateTicket } from '../../hooks/use-can-create-ticket'

export interface TicketLink {
  id: string
  key: string
  url: string
  role: string
  state: 'active' | 'unlinked' | 'deleted'
  source: 'platform' | 'person' | 'migration'
  last_status?: string
  sync_error?: string
}

/**
 * A finding's tracker issues: the linked Jira issues (with their last known
 * status and sync error), any other ticket URL on the finding, and, for who
 * may create tickets, "Link an existing issue" and unlink.
 */
export function FindingTicketLinks({
  findingId,
  workItemUris,
}: {
  findingId: string
  workItemUris?: string[]
}) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const canLink = useCanCreateTicket()
  const key = currentTenant ? `/api/v1/findings/${findingId}/ticket-links` : null
  const { data, mutate } = useSWR<{ links: TicketLink[] }>(
    key,
    (u: string) => get<{ links: TicketLink[] }>(u),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    }
  )
  const [open, setOpen] = useState(false)
  const [issue, setIssue] = useState('')
  const [saving, setSaving] = useState(false)
  const [unlinking, setUnlinking] = useState<TicketLink | null>(null)

  const active = (data?.links ?? []).filter((l) => l.state === 'active')
  const linkedUrls = new Set(active.map((l) => l.url.toLowerCase()))
  const others = (workItemUris ?? []).filter((u) => !linkedUrls.has(u.toLowerCase()))

  const submit = async () => {
    setSaving(true)
    try {
      const l = await post<TicketLink>(`/api/v1/findings/${findingId}/ticket-links`, {
        issue: issue.trim(),
      })
      toast.success(t('findings.ticketLinks.linked', '{key} linked', { key: l.key }))
      setOpen(false)
      setIssue('')
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findings.ticketLinks.linkFailed', 'Could not link the issue'))
      )
    } finally {
      setSaving(false)
    }
  }

  if (active.length === 0 && others.length === 0 && !canLink)
    return <span className="text-muted-foreground">—</span>

  return (
    <span className="flex flex-col gap-1">
      {active.map((l) => (
        <span key={l.id} className="flex min-w-0 flex-wrap items-center gap-1.5">
          <a
            href={sanitizeExternalUrl(l.url)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-medium hover:underline"
          >
            {l.key}
            <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
          </a>
          {l.last_status && (
            <Badge variant="secondary" className="text-[10px]">
              {l.last_status}
            </Badge>
          )}
          {l.sync_error && (
            <Badge variant="destructive" className="text-[10px]" title={l.sync_error}>
              {t('findings.ticketLinks.syncError', 'Sync error')}
            </Badge>
          )}
          {canLink && (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              aria-label={t('findings.ticketLinks.unlinkAria', 'Unlink {key}', { key: l.key })}
              onClick={() => setUnlinking(l)}
            >
              <Unlink className="h-3.5 w-3.5" aria-hidden />
            </Button>
          )}
        </span>
      ))}
      {others.map((uri) => (
        <a
          key={uri}
          href={sanitizeExternalUrl(uri)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex min-w-0 items-center gap-1 text-sm hover:underline"
        >
          <span className="truncate">{uri.replace(/^https?:\/\//, '')}</span>
          <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
        </a>
      ))}
      {canLink && (
        <Button
          variant="link"
          size="sm"
          className="h-auto justify-start p-0 text-xs"
          onClick={() => setOpen(true)}
        >
          <Link2 className="me-1 h-3.5 w-3.5" aria-hidden />
          {t('findings.ticketLinks.linkExisting', 'Link an existing issue')}
        </Button>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>
              {t('findings.ticketLinks.dialogTitle', 'Link an existing Jira issue')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'findings.ticketLinks.dialogDescription',
                'The issue must be on your organization’s Jira site and visible to the integration.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="grid gap-2">
              <Label htmlFor="ticket-link-issue">
                {t('findings.ticketLinks.issueLabel', 'Issue key or URL')}
              </Label>
              <Input
                id="ticket-link-issue"
                value={issue}
                maxLength={2048}
                placeholder="SEC-123"
                onChange={(e) => setIssue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && issue.trim()) void submit()
                }}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              {t('findings.ticketLinks.cancel', 'Cancel')}
            </Button>
            <Button onClick={submit} disabled={saving || !issue.trim()}>
              {t('findings.ticketLinks.link', 'Link')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!unlinking}
        onOpenChange={(o) => !o && setUnlinking(null)}
        title={t('findings.ticketLinks.unlinkTitle', 'Unlink {key}?', {
          key: unlinking?.key ?? '',
        })}
        desc={t(
          'findings.ticketLinks.unlinkDescription',
          'The finding stops syncing with this issue. The issue itself is not changed.'
        )}
        confirmText={t('findings.ticketLinks.unlink', 'Unlink')}
        destructive
        handleConfirm={async () => {
          if (!unlinking) return
          try {
            await del(`/api/v1/findings/${findingId}/ticket-links/${unlinking.id}`)
            setUnlinking(null)
            await mutate()
          } catch (err) {
            toast.error(
              getErrorMessage(
                err,
                t('findings.ticketLinks.unlinkFailed', 'Could not unlink the issue')
              )
            )
          }
        }}
      />
    </span>
  )
}
