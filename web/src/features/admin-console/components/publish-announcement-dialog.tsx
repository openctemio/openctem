'use client'

import { useId, useState } from 'react'
import { Megaphone } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
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
import { publishAnnouncement } from '../api/use-system'
import { AdminConfirmDialog } from './admin-confirm-dialog'
import type { AdminAnnouncement } from '../types'

export const ANNOUNCEMENT_MAX = 500
const MAX_DAYS = 31

/** A datetime-local value (viewer's time zone) for a Date. */
export function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/**
 * Checks a draft the way the API does: one line of 1-500 characters, the end
 * after the start and at most 31 days later. Returns the problem, or null.
 */
export function announcementProblem(message: string, starts: Date, ends: Date): string | null {
  const m = message.trim()
  if (m.length === 0) return 'Write the message.'
  if (m.length > ANNOUNCEMENT_MAX) return `At most ${ANNOUNCEMENT_MAX} characters.`
  if (Number.isNaN(ends.getTime()) || ends <= starts) return 'The end must be after the start.'
  if (ends.getTime() - starts.getTime() > MAX_DAYS * 24 * 3600 * 1000)
    return `At most ${MAX_DAYS} days.`
  return null
}

/**
 * Publish a notice every signed-in user sees as a banner (planned
 * maintenance, a warning). Plain text, one line, a bounded window, and a
 * reason for the audit log.
 */
export function PublishAnnouncementDialog({ onPublished }: { onPublished: () => void }) {
  const { t } = useTranslation()
  const ids = { msg: useId(), sev: useId(), start: useId(), end: useId() }
  const [open, setOpen] = useState(false)
  const [message, setMessage] = useState('')
  const [severity, setSeverity] = useState<AdminAnnouncement['severity']>('maintenance')
  const [starts, setStarts] = useState('')
  const [ends, setEnds] = useState(() => toLocalInput(new Date(Date.now() + 2 * 3600 * 1000)))
  const startDate = starts ? new Date(starts) : new Date()
  const problem = announcementProblem(message, startDate, new Date(ends))

  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)}>
        <Megaphone className="me-2 size-4" />
        {t('admin.ann.publish', 'Publish announcement')}
      </Button>
      <AdminConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={t('admin.ann.publishTitle', 'Publish an announcement')}
        description={
          <p>
            {t(
              'admin.ann.publishWhat',
              'Every signed-in user sees it under the header while it is active. Plain text, one line.'
            )}
          </p>
        }
        confirmLabel={t('admin.ann.publish', 'Publish announcement')}
        canSubmit={problem === null}
        onConfirm={async ({ reason }) => {
          await publishAnnouncement({
            message: message.trim(),
            severity,
            ...(starts ? { starts_at: new Date(starts).toISOString() } : {}),
            ends_at: new Date(ends).toISOString(),
            reason,
          })
          toast.success(t('admin.ann.published', 'Announcement published.'))
          setMessage('')
          setStarts('')
          onPublished()
        }}
      >
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor={ids.msg}>{t('admin.ann.message', 'Message')}</Label>
            <Textarea
              id={ids.msg}
              value={message}
              // One line: line breaks become spaces as they are typed or pasted.
              onChange={(e) => setMessage(e.target.value.replace(/[\r\n]+/g, ' '))}
              maxLength={ANNOUNCEMENT_MAX}
              rows={2}
              placeholder={t(
                'admin.ann.placeholder',
                'Planned maintenance on Saturday 22:00-23:00 UTC: sign-in and scans pause.'
              )}
            />
            <p className="text-xs text-muted-foreground tabular-nums">
              {message.trim().length}/{ANNOUNCEMENT_MAX}
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor={ids.sev}>{t('admin.ann.severity', 'Kind')}</Label>
              <Select
                value={severity}
                onValueChange={(v) => setSeverity(v as AdminAnnouncement['severity'])}
              >
                <SelectTrigger id={ids.sev}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="maintenance">
                    {t('admin.ann.sev.maintenance', 'Maintenance')}
                  </SelectItem>
                  <SelectItem value="warning">{t('admin.ann.sev.warning', 'Warning')}</SelectItem>
                  <SelectItem value="info">{t('admin.ann.sev.info', 'Information')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor={ids.start}>{t('admin.ann.starts', 'Starts (empty = now)')}</Label>
              <Input
                id={ids.start}
                type="datetime-local"
                value={starts}
                onChange={(e) => setStarts(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor={ids.end}>{t('admin.ann.ends', 'Ends')}</Label>
              <Input
                id={ids.end}
                type="datetime-local"
                value={ends}
                onChange={(e) => setEnds(e.target.value)}
                required
              />
            </div>
          </div>
          {problem && message.length > 0 && <p className="text-sm text-destructive">{problem}</p>}
        </div>
      </AdminConfirmDialog>
    </>
  )
}
