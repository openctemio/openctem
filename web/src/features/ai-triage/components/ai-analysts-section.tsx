'use client'

import { useState } from 'react'
import { Bot, Plus } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { DataTableRowActions, EmptyState, TonePill, type RowAction } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'
import { Permission, usePermissions } from '@/lib/permissions'
import { toDisplayText } from '@/lib/untrusted-text'
import { useAuthStore } from '@/stores/auth-store'

import {
  createAIAnalyst,
  deleteAIAnalyst,
  runAIAnalystAction,
  setAIAnalystOwners,
  setAIAnalystPreset,
  useAIAnalysts,
  type AIAnalyst,
  type AIAnalystAction,
  type AIAnalystPreset,
  type AIOwnerInput,
} from '../api/use-ai-analysts'
import { AIAnalystOwnerPicker } from './ai-analyst-owner-picker'

type Translate = ReturnType<typeof useTranslation>['t']

const PRESETS: AIAnalystPreset[] = ['suggest', 'triage']

function presetName(t: Translate, p: string): string {
  return p === 'triage'
    ? t('settings.ai.analysts.preset.triage', 'Triage')
    : t('settings.ai.analysts.preset.suggest', 'Suggest')
}

function presetHint(t: Translate, p: AIAnalystPreset): string {
  return p === 'triage'
    ? t(
        'settings.ai.analysts.preset.triageHint',
        'Reads findings, comments and opens approval requests, and can also change status, severity and assignment like a person with that role.'
      )
    : t(
        'settings.ai.analysts.preset.suggestHint',
        'Reads findings, comments and opens approval requests. It never changes a finding itself.'
      )
}

function reasonText(t: Translate, reason: string | undefined): string | undefined {
  switch (reason) {
    case 'no_active_owner':
      return t('settings.ai.analysts.reason.noActiveOwner', 'No active accountable owner')
    case 'attestation_expired':
      return t('settings.ai.analysts.reason.attestationExpired', 'Attestation overdue')
    case 'admin':
      return t('settings.ai.analysts.reason.admin', 'Paused by an administrator')
    case 'no_permissions':
      return t('settings.ai.analysts.reason.noPermissions', 'Missing permissions')
    default:
      return undefined
  }
}

function StatusPill({ analyst }: { analyst: AIAnalyst }) {
  const { t } = useTranslation()
  const reason = analyst.status === 'active' ? undefined : reasonText(t, analyst.pause_reason || '')
  if (analyst.status === 'active') {
    return <TonePill tone="success" label={t('settings.ai.analysts.status.active', 'Active')} />
  }
  if (analyst.status === 'paused') {
    return (
      <TonePill
        tone="warning"
        label={t('settings.ai.analysts.status.paused', 'Paused')}
        detail={reason}
      />
    )
  }
  return (
    <TonePill
      tone="muted"
      label={t('settings.ai.analysts.status.disabled', 'Disabled')}
      detail={reason}
    />
  )
}

type Pending =
  | { kind: 'action'; action: AIAnalystAction; analyst: AIAnalyst }
  | { kind: 'delete'; analyst: AIAnalyst }

/**
 * Settings > AI > AI analysts: the service accounts that take part in triage
 * like a person, each with accountable owners (API docs:
 * architecture/ai-analysis.md). Managing them needs `service_accounts:manage`;
 * an accountable owner may also attest and pause their own analyst. The API
 * stays the authority.
 */
export function AIAnalystsSection() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const userId = useAuthStore((s) => s.user?.id)
  const canManage = can(Permission.ServiceAccountsManage)
  const analysts = useAIAnalysts(true)

  const [createOpen, setCreateOpen] = useState(false)
  const [ownersFor, setOwnersFor] = useState<AIAnalyst | null>(null)
  const [presetFor, setPresetFor] = useState<AIAnalyst | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)

  const rows = analysts.data ?? []

  const actionsOf = (a: AIAnalyst): RowAction[] => {
    const isOwner = !!userId && a.owners.some((o) => o.kind === 'user' && o.id === userId)
    const out: RowAction[] = []
    if ((canManage || isOwner) && a.status !== 'disabled') {
      out.push({
        label: t('settings.ai.analysts.action.attest', 'Attest'),
        onClick: () => setPending({ kind: 'action', action: 'attest', analyst: a }),
      })
    }
    if ((canManage || isOwner) && a.status === 'active') {
      out.push({
        label: t('settings.ai.analysts.action.pause', 'Pause'),
        onClick: () => setPending({ kind: 'action', action: 'pause', analyst: a }),
      })
    }
    if (canManage) {
      if (a.status === 'paused') {
        out.push({
          label: t('settings.ai.analysts.action.resume', 'Resume'),
          onClick: () => setPending({ kind: 'action', action: 'resume', analyst: a }),
        })
      }
      out.push(
        {
          label: t('settings.ai.analysts.action.owners', 'Change owners'),
          onClick: () => setOwnersFor(a),
          separatorBefore: out.length > 0,
        },
        {
          label: t('settings.ai.analysts.action.preset', 'Change preset'),
          onClick: () => setPresetFor(a),
        }
      )
      if (a.status !== 'disabled') {
        out.push({
          label: t('settings.ai.analysts.action.disable', 'Disable'),
          onClick: () => setPending({ kind: 'action', action: 'disable', analyst: a }),
          separatorBefore: true,
        })
      }
      out.push({
        label: t('settings.ai.analysts.action.delete', 'Delete'),
        destructive: true,
        onClick: () => setPending({ kind: 'delete', analyst: a }),
        separatorBefore: a.status === 'disabled',
      })
    }
    return out
  }

  const confirmPending = async () => {
    if (!pending) return
    try {
      if (pending.kind === 'delete') {
        await deleteAIAnalyst(pending.analyst.id)
        toast.success(t('settings.ai.analysts.toast.deleted', 'AI analyst deleted'))
      } else {
        await runAIAnalystAction(pending.analyst.id, pending.action)
        toast.success(actionToast(t, pending.action))
      }
      await analysts.mutate()
      setPending(null)
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  return (
    <Card id="ai-analysts">
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <Bot className="h-4 w-4" aria-hidden />
            {t('settings.ai.analysts.title', 'AI analysts')}
          </CardTitle>
          <CardDescription>
            {t(
              'settings.ai.analysts.description',
              'An AI analyst takes part in triage like a person, as its own service account. People or teams are accountable for it and must attest to it on a schedule; without an active owner it pauses.'
            )}
          </CardDescription>
        </div>
        {canManage && (
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="me-1 h-4 w-4" aria-hidden />
            {t('settings.ai.analysts.create', 'New AI analyst')}
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {analysts.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : analysts.error ? (
          <p className="text-sm text-destructive">{getErrorMessage(analysts.error)}</p>
        ) : rows.length === 0 ? (
          <EmptyState
            icon={Bot}
            title={t('settings.ai.analysts.empty.title', 'No AI analysts yet')}
            description={t(
              'settings.ai.analysts.empty.description',
              'Create one to let AI help triage findings under the accountability of your people.'
            )}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('settings.ai.analysts.col.name', 'Name')}</TableHead>
                <TableHead>{t('settings.ai.analysts.col.preset', 'Preset')}</TableHead>
                <TableHead>{t('settings.ai.analysts.col.status', 'Status')}</TableHead>
                <TableHead>{t('settings.ai.analysts.col.owners', 'Accountable')}</TableHead>
                <TableHead>{t('settings.ai.analysts.col.attestDue', 'Attest by')}</TableHead>
                <TableHead className="w-10">
                  <span className="sr-only">
                    {t('settings.ai.analysts.col.actions', 'Actions')}
                  </span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((a) => (
                <TableRow key={a.id} data-testid="ai-analyst-row">
                  <TableCell className="font-medium">{toDisplayText(a.name, 80)}</TableCell>
                  <TableCell>{presetName(t, a.preset)}</TableCell>
                  <TableCell>
                    <StatusPill analyst={a} />
                  </TableCell>
                  <TableCell>
                    {a.owners.map((o) => toDisplayText(o.name, 80)).join(', ') || '—'}
                  </TableCell>
                  <TableCell>{formatDateSafe(a.attest_due_at)}</TableCell>
                  <TableCell>
                    <DataTableRowActions
                      actions={actionsOf(a)}
                      label={t('settings.ai.analysts.rowActions', 'Actions for {name}', {
                        name: toDisplayText(a.name, 80),
                      })}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <CreateDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        tenant={currentTenant?.slug}
        onCreated={async () => {
          await analysts.mutate()
        }}
      />
      {ownersFor && (
        <OwnersDialog
          analyst={ownersFor}
          tenant={currentTenant?.slug}
          onClose={() => setOwnersFor(null)}
          onSaved={async () => {
            await analysts.mutate()
          }}
        />
      )}
      {presetFor && (
        <PresetDialog
          analyst={presetFor}
          onClose={() => setPresetFor(null)}
          onSaved={async () => {
            await analysts.mutate()
          }}
        />
      )}
      <ConfirmDialog
        open={!!pending}
        onOpenChange={(o) => !o && setPending(null)}
        destructive={pending?.kind === 'delete' || pending?.action === 'disable'}
        title={pending ? confirmTitle(t, pending) : ''}
        desc={pending ? confirmDesc(t, pending) : ''}
        confirmText={pending ? confirmLabel(t, pending) : ''}
        handleConfirm={confirmPending}
      />
    </Card>
  )
}

function actionOf(p: Pending): AIAnalystAction | 'delete' {
  return p.kind === 'delete' ? 'delete' : p.action
}

function actionToast(t: Translate, a: AIAnalystAction): string {
  switch (a) {
    case 'attest':
      return t('settings.ai.analysts.toast.attest', 'Attestation recorded')
    case 'pause':
      return t('settings.ai.analysts.toast.pause', 'AI analyst paused')
    case 'resume':
      return t('settings.ai.analysts.toast.resume', 'AI analyst resumed')
    default:
      return t('settings.ai.analysts.toast.disable', 'AI analyst disabled')
  }
}

function confirmLabel(t: Translate, p: Pending): string {
  switch (actionOf(p)) {
    case 'attest':
      return t('settings.ai.analysts.action.attest', 'Attest')
    case 'pause':
      return t('settings.ai.analysts.action.pause', 'Pause')
    case 'resume':
      return t('settings.ai.analysts.action.resume', 'Resume')
    case 'disable':
      return t('settings.ai.analysts.action.disable', 'Disable')
    default:
      return t('settings.ai.analysts.action.delete', 'Delete')
  }
}

function confirmTitle(t: Translate, p: Pending): string {
  const name = toDisplayText(p.analyst.name, 80)
  switch (actionOf(p)) {
    case 'attest':
      return t('settings.ai.analysts.confirm.attestTitle', 'Attest to {name}?', { name })
    case 'pause':
      return t('settings.ai.analysts.confirm.pauseTitle', 'Pause {name}?', { name })
    case 'resume':
      return t('settings.ai.analysts.confirm.resumeTitle', 'Resume {name}?', { name })
    case 'disable':
      return t('settings.ai.analysts.confirm.disableTitle', 'Disable {name}?', { name })
    default:
      return t('settings.ai.analysts.confirm.deleteTitle', 'Delete {name}?', { name })
  }
}

function confirmDesc(t: Translate, p: Pending): string {
  switch (actionOf(p)) {
    case 'attest':
      return t(
        'settings.ai.analysts.confirm.attestDesc',
        'You confirm that you are accountable for what this AI analyst does and that its permissions are still right.'
      )
    case 'pause':
      return t(
        'settings.ai.analysts.confirm.pauseDesc',
        'It stops acting on findings until it is resumed. Nothing it already did is undone.'
      )
    case 'resume':
      return t(
        'settings.ai.analysts.confirm.resumeDesc',
        'It starts acting on findings again with its current preset and owners. This needs a recent sign-in.'
      )
    case 'disable':
      return t(
        'settings.ai.analysts.confirm.disableDesc',
        'It stops acting and cannot be resumed until an administrator turns it back on. Its history stays.'
      )
    default:
      return t(
        'settings.ai.analysts.confirm.deleteDesc',
        'The service account and its access are removed. What it did stays in each finding’s history. This needs a recent sign-in.'
      )
  }
}

function PresetSelect({
  id,
  value,
  onChange,
  disabled,
}: {
  id: string
  value: AIAnalystPreset
  onChange: (v: AIAnalystPreset) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1.5">
      <Select
        value={value}
        onValueChange={(v) => onChange(v as AIAnalystPreset)}
        disabled={disabled}
      >
        <SelectTrigger id={id}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {PRESETS.map((p) => (
            <SelectItem key={p} value={p}>
              {presetName(t, p)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-xs text-muted-foreground">{presetHint(t, value)}</p>
    </div>
  )
}

function CreateDialog({
  open,
  onOpenChange,
  tenant,
  onCreated,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  tenant: string | undefined
  onCreated: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [preset, setPreset] = useState<AIAnalystPreset>('suggest')
  const [owners, setOwners] = useState<AIOwnerInput[]>([])
  const [busy, setBusy] = useState(false)

  const reset = () => {
    setName('')
    setDescription('')
    setPreset('suggest')
    setOwners([])
  }
  const submit = async () => {
    setBusy(true)
    try {
      await createAIAnalyst({
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        preset,
        owners,
      })
      toast.success(t('settings.ai.analysts.toast.created', 'AI analyst created'))
      await onCreated()
      reset()
      onOpenChange(false)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (busy ? undefined : onOpenChange(o))}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('settings.ai.analysts.createTitle', 'New AI analyst')}</DialogTitle>
          <DialogDescription>
            {t(
              'settings.ai.analysts.createDesc',
              'Creating an AI analyst needs a recent sign-in. At least one accountable person or team is required.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="grid gap-4">
          <div className="space-y-1.5">
            <Label htmlFor="ai-analyst-name">{t('settings.ai.analysts.field.name', 'Name')}</Label>
            <Input
              id="ai-analyst-name"
              value={name}
              maxLength={100}
              onChange={(e) => setName(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ai-analyst-description">
              {t('settings.ai.analysts.field.description', 'Description (optional)')}
            </Label>
            <Textarea
              id="ai-analyst-description"
              value={description}
              maxLength={500}
              onChange={(e) => setDescription(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ai-analyst-preset">
              {t('settings.ai.analysts.field.preset', 'Preset')}
            </Label>
            <PresetSelect
              id="ai-analyst-preset"
              value={preset}
              onChange={setPreset}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label>{t('settings.ai.analysts.field.owners', 'Accountable owners')}</Label>
            <AIAnalystOwnerPicker
              tenant={tenant}
              value={owners}
              onChange={setOwners}
              disabled={busy}
            />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={busy || !name.trim() || owners.length === 0}>
            {t('settings.ai.analysts.createSubmit', 'Create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function OwnersDialog({
  analyst,
  tenant,
  onClose,
  onSaved,
}: {
  analyst: AIAnalyst
  tenant: string | undefined
  onClose: () => void
  onSaved: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [owners, setOwners] = useState<AIOwnerInput[]>(
    analyst.owners.map((o) => ({ kind: o.kind, id: o.id }))
  )
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      await setAIAnalystOwners(analyst.id, owners)
      toast.success(t('settings.ai.analysts.toast.owners', 'Accountable owners updated'))
      await onSaved()
      onClose()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {t('settings.ai.analysts.ownersTitle', 'Accountable owners of {name}', {
              name: toDisplayText(analyst.name, 80),
            })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.ai.analysts.ownersDesc',
              'These people and teams answer for what the AI analyst does. At least one is required.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <AIAnalystOwnerPicker
            tenant={tenant}
            value={owners}
            onChange={setOwners}
            disabled={busy}
          />
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={busy || owners.length === 0}>
            {t('settings.ai.analysts.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function PresetDialog({
  analyst,
  onClose,
  onSaved,
}: {
  analyst: AIAnalyst
  onClose: () => void
  onSaved: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [preset, setPreset] = useState<AIAnalystPreset>(analyst.preset)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      await setAIAnalystPreset(analyst.id, preset)
      toast.success(t('settings.ai.analysts.toast.preset', 'Preset updated'))
      await onSaved()
      onClose()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>
            {t('settings.ai.analysts.presetTitle', 'Preset of {name}', {
              name: toDisplayText(analyst.name, 80),
            })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.ai.analysts.presetDesc',
              'A wider preset needs an accountable person who holds its permissions. This needs a recent sign-in.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <PresetSelect
            id="ai-analyst-preset-edit"
            value={preset}
            onChange={setPreset}
            disabled={busy}
          />
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={busy || preset === analyst.preset}>
            {t('settings.ai.analysts.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
