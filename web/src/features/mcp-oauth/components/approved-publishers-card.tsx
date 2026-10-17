'use client'

import { useState } from 'react'
import { Globe, Loader2, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Label } from '@/components/ui/label'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'

import { type McpPolicy, patchMcpPolicy } from '../api/connections'
import { normalizePublisherHost } from '../lib/use-mcp-labels'

interface ApprovedPublishersCardProps {
  policy: McpPolicy
  canEdit: boolean
}

/**
 * Publishers (hosts of client metadata documents) whose applications members
 * may connect: the organization's own list, editable, and the platform's,
 * read only. Every change is saved at once and needs a recent sign-in.
 */
export function ApprovedPublishersCard({ policy, canEdit }: ApprovedPublishersCardProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')
  const [touched, setTouched] = useState(false)
  const [saving, setSaving] = useState(false)
  const [removing, setRemoving] = useState<string | null>(null)

  const host = normalizePublisherHost(value)
  const duplicate = host !== null && policy.client_hosts.includes(host)
  const full = policy.client_hosts.length >= 50
  const error = !touched
    ? null
    : !host
      ? t(
          'mcp.publishers.invalid',
          'Enter a host name such as assistant.example.com (no wildcard, path or single word).'
        )
      : duplicate
        ? t('mcp.publishers.duplicate', 'This publisher is already approved.')
        : null

  const add = async () => {
    setTouched(true)
    if (!host || duplicate) return
    setSaving(true)
    try {
      await patchMcpPolicy(policy, { client_hosts: [...policy.client_hosts, host] })
      toast.success(t('mcp.publishers.added', '{host} approved', { host }))
      setOpen(false)
      setValue('')
      setTouched(false)
    } catch (err) {
      toast.error(getErrorMessage(err, t('mcp.publishers.saveFailed', 'Could not save')))
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!removing) return
    setSaving(true)
    try {
      await patchMcpPolicy(policy, {
        client_hosts: policy.client_hosts.filter((h) => h !== removing),
      })
      toast.success(t('mcp.publishers.removed', '{host} removed', { host: removing }))
      setRemoving(null)
    } catch (err) {
      toast.error(getErrorMessage(err, t('mcp.publishers.saveFailed', 'Could not save')))
    } finally {
      setSaving(false)
    }
  }

  const empty = policy.client_hosts.length === 0 && policy.platform_client_hosts.length === 0

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div className="space-y-1.5">
          <CardTitle>{t('mcp.publishers.title', 'Approved publishers')}</CardTitle>
          <CardDescription>
            {t(
              'mcp.publishers.description',
              'Members can connect applications whose identity is published on these hosts. The consent page shows the publisher, so a lookalike application cannot borrow the name.'
            )}
          </CardDescription>
        </div>
        {canEdit && (
          <Button size="sm" className="shrink-0" onClick={() => setOpen(true)} disabled={full}>
            <Plus className="mr-2 h-4 w-4" aria-hidden />
            {t('mcp.publishers.add', 'Add publisher')}
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {empty ? (
          <EmptyState
            icon={Globe}
            title={t('mcp.publishers.emptyTitle', 'No approved publishers')}
            description={t(
              'mcp.publishers.emptyDescription',
              'Only applications your organization registered can be connected. Approve a publisher here, or from a member’s request.'
            )}
          />
        ) : (
          <ul className="divide-y rounded-md border">
            {policy.client_hosts.map((h) => (
              <li key={h} className="flex items-center justify-between gap-3 px-4 py-3">
                <div className="flex min-w-0 items-center gap-2">
                  <ShieldCheck className="text-muted-foreground h-4 w-4 shrink-0" aria-hidden />
                  <span className="font-mono text-sm break-all">{h}</span>
                </div>
                {canEdit && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="shrink-0"
                    onClick={() => setRemoving(h)}
                    aria-label={t('mcp.publishers.removeLabel', 'Remove {host}', { host: h })}
                  >
                    <Trash2 className="h-4 w-4 sm:mr-2" aria-hidden />
                    <span className="sr-only sm:not-sr-only">
                      {t('mcp.publishers.remove', 'Remove')}
                    </span>
                  </Button>
                )}
              </li>
            ))}
            {policy.platform_client_hosts.map((h) => (
              <li
                key={`platform-${h}`}
                className="flex items-center justify-between gap-3 px-4 py-3"
              >
                <div className="flex min-w-0 items-center gap-2">
                  <ShieldCheck className="text-muted-foreground h-4 w-4 shrink-0" aria-hidden />
                  <span className="font-mono text-sm break-all">{h}</span>
                </div>
                <Badge variant="outline" className="shrink-0">
                  {t('mcp.publishers.platform', 'Trusted by the platform')}
                </Badge>
              </li>
            ))}
          </ul>
        )}
        {full && canEdit && (
          <p className="text-muted-foreground mt-2 text-xs">
            {t('mcp.publishers.full', 'At most 50 publishers. Remove one to add another.')}
          </p>
        )}
      </CardContent>

      <Dialog open={open} onOpenChange={(v) => !saving && setOpen(v)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('mcp.publishers.addTitle', 'Approve a publisher')}</DialogTitle>
            <DialogDescription>
              {t(
                'mcp.publishers.addDesc',
                'Every member can then connect applications whose identity document is published on this host. Each person still approves what it may do.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <form
              className="space-y-2"
              onSubmit={(e) => {
                e.preventDefault()
                void add()
              }}
            >
              <Label htmlFor="mcp-publisher-host">
                {t('mcp.publishers.hostLabel', 'Host name')}
              </Label>
              <Input
                id="mcp-publisher-host"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                onBlur={() => setTouched(true)}
                placeholder="assistant.example.com"
                autoComplete="off"
                aria-invalid={error ? true : undefined}
                aria-describedby="mcp-publisher-host-help"
              />
              <p
                id="mcp-publisher-host-help"
                className={error ? 'text-destructive text-xs' : 'text-muted-foreground text-xs'}
              >
                {error ??
                  t(
                    'mcp.publishers.hostHelp',
                    'You can paste the application’s address; only its host is kept.'
                  )}
              </p>
            </form>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={saving}>
              {t('mcp.common.cancel', 'Cancel')}
            </Button>
            <Button onClick={() => void add()} disabled={saving || !value.trim()}>
              {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
              {t('mcp.publishers.approve', 'Approve')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => !v && !saving && setRemoving(null)}
        destructive
        title={t('mcp.publishers.removeTitle', 'Remove {host}?', { host: removing ?? '' })}
        desc={t(
          'mcp.publishers.removeDesc',
          'Applications published there can no longer be connected, and their existing connections stop working at their next request.'
        )}
        confirmText={t('mcp.publishers.remove', 'Remove')}
        isLoading={saving}
        handleConfirm={() => remove()}
      />
    </Card>
  )
}
