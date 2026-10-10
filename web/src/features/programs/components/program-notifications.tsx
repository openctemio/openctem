'use client'

/**
 * Where events about a private program's assets go (RFC-065 §15.4).
 *
 * Organization-wide integrations (a Slack channel, a webhook, a SIEM index)
 * reach people outside the program, so those events go only to the
 * notification integrations attached here. Attaching needs programs:write
 * and integrations:manage; only an owner may also send them to every
 * organization channel, with a reason. The API decides and re-checks all of
 * it (membership, accepted terms, owner, step-up); this view only reflects
 * it. Attach and the opt-in ask for step-up, which the shared client handles.
 */

import { useId, useState } from 'react'
import { toast } from 'sonner'
import { Loader2, Trash2 } from 'lucide-react'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type { Program, ProgramChannel } from '../api/programs-api.types'
import {
  attachProgramChannel,
  detachProgramChannel,
  setProgramOrgChannels,
  useNotificationChannelOptions,
  useProgramDelivery,
} from '../api/use-programs'

/** Reason bounds for the organization-channel opt-in (the API checks them too). */
export const OPT_IN_REASON_MIN = 10
export const OPT_IN_REASON_MAX = 500

interface ProgramNotificationsProps {
  program: Program
  /** programs:write and integrations:manage: may attach and detach channels. */
  canManage: boolean
  /** The caller owns the organization: may change the organization-channel opt-in. */
  isOwner: boolean
}

export function ProgramNotifications({
  program: p,
  canManage,
  isOwner,
}: ProgramNotificationsProps) {
  const { t } = useTranslation()
  const reasonId = useId()
  const {
    data: delivery,
    error,
    mutate,
  } = useProgramDelivery(p.visibility === 'private' ? p.id : null)
  const { data: options } = useNotificationChannelOptions(canManage && p.visibility === 'private')
  const [selected, setSelected] = useState('')
  const [busy, setBusy] = useState(false)
  const [detaching, setDetaching] = useState<ProgramChannel | null>(null)
  const [optIn, setOptIn] = useState<boolean | null>(null) // the value being confirmed
  const [reason, setReason] = useState('')

  if (p.visibility !== 'private') return null

  const fail = (err: unknown) =>
    toast.error(
      err instanceof ApiClientError ? err.message : t('programs.failed', 'The change failed')
    )

  const run = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true)
    try {
      await fn()
      toast.success(done)
      await mutate()
      return true
    } catch (err) {
      fail(err)
      return false
    } finally {
      setBusy(false)
    }
  }

  const attached = new Set((delivery?.channels ?? []).map((c) => c.integration_id))
  const available = (options ?? []).filter((o) => !attached.has(o.id))
  const reasonLen = reason.trim().length
  const reasonOk =
    optIn === false || (reasonLen >= OPT_IN_REASON_MIN && reasonLen <= OPT_IN_REASON_MAX)

  const attach = async () => {
    if (!selected) return
    if (
      await run(
        () => attachProgramChannel(p.id, selected),
        t('programs.notify.attached', 'Channel attached')
      )
    ) {
      setSelected('')
    }
  }

  const confirmDetach = async () => {
    if (!detaching) return
    await run(
      () => detachProgramChannel(p.id, detaching.integration_id),
      t('programs.notify.detached', 'Channel detached')
    )
    setDetaching(null)
  }

  const confirmOptIn = async () => {
    if (optIn === null || !reasonOk) return
    const ok = await run(
      () => setProgramOrgChannels(p.id, optIn, optIn ? reason.trim() : ''),
      optIn
        ? t('programs.notify.orgOn', 'Events now also go to organization channels')
        : t('programs.notify.orgOff', 'Events no longer go to organization channels')
    )
    if (ok) {
      setOptIn(null)
      setReason('')
    }
  }

  return (
    <section className="space-y-3 rounded-md border p-4" aria-labelledby={`${reasonId}-title`}>
      <h3 id={`${reasonId}-title`} className="text-base font-semibold">
        {t('programs.notify.title', 'Notifications')}
      </h3>
      <p className="text-muted-foreground text-sm">
        {t(
          'programs.notify.hint',
          'Events about this private program assets do not go to organization-wide channels by default: they reach only the channels attached here, with the program name. Every other channel sees "[private program]" instead of its name.'
        )}
      </p>

      {error && (
        <p className="text-destructive text-sm">
          {t('programs.notify.loadFailed', 'The notification settings could not be loaded.')}
        </p>
      )}
      {!delivery && !error && <Loader2 className="h-4 w-4 animate-spin" />}

      {delivery && (
        <>
          {delivery.channels.length === 0 ? (
            <p className="text-sm">{t('programs.notify.none', 'No channel is attached.')}</p>
          ) : (
            <ul className="divide-y rounded-md border">
              {delivery.channels.map((c) => (
                <li
                  key={c.integration_id}
                  className="flex min-w-0 items-center justify-between gap-2 px-3 py-2"
                >
                  <span className="min-w-0 truncate text-sm">
                    <span className="font-medium">{c.name}</span>{' '}
                    <span className="text-muted-foreground text-xs">{c.provider}</span>
                  </span>
                  {canManage && (
                    <Button
                      variant="ghost"
                      size="icon"
                      disabled={busy}
                      onClick={() => setDetaching(c)}
                      aria-label={t('programs.notify.detachAria', 'Detach {name}', {
                        name: c.name,
                      })}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}

          {canManage ? (
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <Select value={selected} onValueChange={setSelected} disabled={busy}>
                <SelectTrigger
                  className="w-full sm:w-72"
                  aria-label={t('programs.notify.pick', 'Choose a notification channel')}
                >
                  <SelectValue
                    placeholder={t('programs.notify.pick', 'Choose a notification channel')}
                  />
                </SelectTrigger>
                <SelectContent>
                  {available.map((o) => (
                    <SelectItem key={o.id} value={o.id}>
                      {o.name} ({o.provider})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button onClick={attach} disabled={busy || !selected}>
                {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t('programs.notify.attach', 'Attach channel')}
              </Button>
              {options && available.length === 0 && (
                <span className="text-muted-foreground text-xs">
                  {t(
                    'programs.notify.noOptions',
                    'No other notification integration to attach. Add one in Settings, Integrations.'
                  )}
                </span>
              )}
            </div>
          ) : (
            <p className="text-muted-foreground text-xs">
              {t(
                'programs.notify.needManage',
                'Changing channels needs permission to edit programs and to manage integrations.'
              )}
            </p>
          )}

          <div className="space-y-1 border-t pt-3">
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor={`${reasonId}-org`} className="font-normal">
                {t('programs.notify.orgLabel', 'Also send to organization channels')}
              </Label>
              <Switch
                id={`${reasonId}-org`}
                checked={delivery.org_channels}
                disabled={!isOwner || busy}
                onCheckedChange={(v) => {
                  setReason('')
                  setOptIn(v)
                }}
              />
            </div>
            <p className="text-muted-foreground text-xs">
              {isOwner
                ? t(
                    'programs.notify.orgHint',
                    'Sends these events to every organization-wide channel too, with the program name still hidden. Needs a reason and a fresh sign-in, and is recorded in the audit log.'
                  )
                : t(
                    'programs.notify.orgOwnerOnly',
                    'Only an organization owner can change this, because it widens who receives events covered by the program terms.'
                  )}
            </p>
          </div>
        </>
      )}

      <ConfirmDialog
        open={detaching !== null}
        onOpenChange={(o) => !o && setDetaching(null)}
        title={t('programs.notify.detachTitle', 'Detach this channel?')}
        desc={t(
          'programs.notify.detachDesc',
          'Events about this program private assets stop going to {name}.',
          { name: detaching?.name ?? '' }
        )}
        destructive
        isLoading={busy}
        confirmText={t('programs.notify.detach', 'Detach')}
        cancelBtnText={t('common.cancel', 'Cancel')}
        handleConfirm={confirmDetach}
      />

      <ConfirmDialog
        open={optIn !== null}
        onOpenChange={(o) => {
          if (!o) {
            setOptIn(null)
            setReason('')
          }
        }}
        title={
          optIn
            ? t('programs.notify.orgOnTitle', 'Send to organization channels?')
            : t('programs.notify.orgOffTitle', 'Stop sending to organization channels?')
        }
        desc={
          optIn
            ? t(
                'programs.notify.orgOnDesc',
                'Every organization-wide channel will receive events about this program private assets, including people outside the program. You will be asked to sign in again.'
              )
            : t(
                'programs.notify.orgOffDesc',
                'Events go back to the attached channels only. You will be asked to sign in again.'
              )
        }
        destructive={optIn === true}
        disabled={!reasonOk}
        isLoading={busy}
        confirmText={
          optIn
            ? t('programs.notify.orgOnConfirm', 'Send to organization channels')
            : t('programs.notify.orgOffConfirm', 'Stop sending')
        }
        cancelBtnText={t('common.cancel', 'Cancel')}
        handleConfirm={confirmOptIn}
      >
        {optIn && (
          <div className="space-y-2">
            <Label htmlFor={`${reasonId}-reason`}>
              {t('programs.notify.reason', 'Reason (recorded in the audit log)')}
            </Label>
            <Textarea
              id={`${reasonId}-reason`}
              value={reason}
              maxLength={OPT_IN_REASON_MAX}
              onChange={(e) => setReason(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">
              {t('programs.notify.reasonHint', '{min} to {max} characters ({n} now)', {
                min: OPT_IN_REASON_MIN,
                max: OPT_IN_REASON_MAX,
                n: reasonLen,
              })}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </section>
  )
}
