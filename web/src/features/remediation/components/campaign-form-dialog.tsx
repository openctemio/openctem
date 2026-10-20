'use client'

/**
 * Create or edit a campaign: name, description, priority, owner, team, start
 * and due date. An edit sends the version it read; a stale save (409) asks to
 * reload, and a refusal (such as moving the due date later) shows the API's
 * message inline.
 */

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'
import {
  CAMPAIGN_PRIORITIES,
  type CampaignFields,
  type CampaignPriority,
  type RemediationCampaign,
} from '../api/use-remediation-campaigns'

const NONE = '__none__'

const day = (iso?: string) => (iso ? iso.slice(0, 10) : '')

export function CampaignFormDialog({
  open,
  onOpenChange,
  campaign,
  onSubmit,
  onReload,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The campaign to edit; absent = create. */
  campaign?: RemediationCampaign
  /** Saves; throws the API error to show. */
  onSubmit: (fields: CampaignFields & { name: string }) => Promise<void>
  /** Reloads the campaign after a stale save. */
  onReload?: () => void
}) {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [priority, setPriority] = useState<CampaignPriority>('medium')
  const [user, setUser] = useState(NONE)
  const [group, setGroup] = useState(NONE)
  const [start, setStart] = useState('')
  const [due, setDue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [stale, setStale] = useState(false)

  useEffect(() => {
    if (!open) return
    setName(campaign?.name ?? '')
    setDescription(campaign?.description ?? '')
    setPriority(campaign?.priority ?? 'medium')
    setUser(campaign?.assigned_to || NONE)
    setGroup(campaign?.assigned_team || NONE)
    setStart(day(campaign?.start_date))
    setDue(day(campaign?.due_date))
    setError(null)
    setStale(false)
  }, [open, campaign])

  const editing = !!campaign
  const submit = async () => {
    setBusy(true)
    setError(null)
    setStale(false)
    const fields: CampaignFields & { name: string } = {
      name: name.trim(),
      description: description.trim(),
      priority,
    }
    if (editing) {
      // An edit sends every field: empty clears it.
      fields.assigned_to = user === NONE ? null : user
      fields.assigned_team = group === NONE ? null : group
      if (start !== day(campaign?.start_date)) fields.start_date = start || null
      if (due !== day(campaign?.due_date)) fields.due_date = due || null
    } else {
      if (user !== NONE) fields.assigned_to = user
      if (group !== NONE) fields.assigned_team = group
      if (start) fields.start_date = start
      if (due) fields.due_date = due
    }
    try {
      await onSubmit(fields)
      onOpenChange(false)
    } catch (err) {
      if (editing && err instanceof ApiClientError && err.statusCode === 409) setStale(true)
      else
        setError(
          err instanceof ApiClientError && err.message
            ? err.message
            : t('remediationCampaigns.toast.failed')
        )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {editing
              ? t('remediationCampaigns.form.editTitle')
              : t('remediationCampaigns.form.createTitle')}
          </DialogTitle>
          <DialogDescription>{t('remediationCampaigns.form.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="campaign-name">{t('remediationCampaigns.form.name')}</Label>
            <Input
              id="campaign-name"
              value={name}
              maxLength={200}
              required
              aria-required
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="campaign-description">
              {t('remediationCampaigns.form.descriptionField')}
            </Label>
            <Textarea
              id="campaign-description"
              value={description}
              maxLength={2000}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="campaign-priority">{t('remediationCampaigns.form.priority')}</Label>
              <Select value={priority} onValueChange={(v) => setPriority(v as CampaignPriority)}>
                <SelectTrigger id="campaign-priority">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CAMPAIGN_PRIORITIES.map((p) => (
                    <SelectItem key={p} value={p}>
                      {t(`remediationCampaigns.priority.${p}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="campaign-owner">{t('remediationCampaigns.form.owner')}</Label>
              <Select value={user} onValueChange={setUser}>
                <SelectTrigger id="campaign-owner">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE}>{t('remediationCampaigns.form.noOwner')}</SelectItem>
                  {owners.users.map((u) => (
                    <SelectItem key={u.id} value={u.id}>
                      {u.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="campaign-team">{t('remediationCampaigns.form.team')}</Label>
              <Select value={group} onValueChange={setGroup}>
                <SelectTrigger id="campaign-team">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE}>{t('remediationCampaigns.form.noTeam')}</SelectItem>
                  {owners.groups.map((g) => (
                    <SelectItem key={g.id} value={g.id}>
                      {g.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="hidden sm:block" />
            <div className="space-y-1.5">
              <Label htmlFor="campaign-start">{t('remediationCampaigns.form.start')}</Label>
              <Input
                id="campaign-start"
                type="date"
                value={start}
                onChange={(e) => setStart(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="campaign-due">{t('remediationCampaigns.form.due')}</Label>
              <Input
                id="campaign-due"
                type="date"
                value={due}
                onChange={(e) => setDue(e.target.value)}
              />
            </div>
          </div>
          {stale && (
            <div
              role="alert"
              className="flex flex-wrap items-center gap-2 text-sm text-destructive"
            >
              {t('remediationCampaigns.form.stale')}
              {onReload && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    onReload()
                    onOpenChange(false)
                  }}
                >
                  {t('remediationCampaigns.actions.reload')}
                </Button>
              )}
            </div>
          )}
          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('remediationCampaigns.actions.cancel')}
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !name.trim()}>
            {busy && <Loader2 className="me-2 size-4 animate-spin" aria-hidden />}
            {editing
              ? t('remediationCampaigns.actions.save')
              : t('remediationCampaigns.actions.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
