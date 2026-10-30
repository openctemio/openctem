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
  createAIAgent,
  deleteAIAgent,
  runAIAgentAction,
  setAIAgentOwners,
  setAIAgentPreset,
  useAIAgents,
  type AIAgent,
  type AIAgentAction,
  type AIAgentPreset,
  type AIOwnerInput,
} from '../api/use-ai-agents'
import { AIAgentOwnerPicker } from './ai-agent-owner-picker'

type Translate = ReturnType<typeof useTranslation>['t']

const PRESETS: AIAgentPreset[] = ['suggest', 'triage']

function presetName(t: Translate, p: string): string {
  return p === 'triage'
    ? t('settings.ai.agents.preset.triage', 'Triage')
    : t('settings.ai.agents.preset.suggest', 'Suggest')
}

function presetHint(t: Translate, p: AIAgentPreset): string {
  return p === 'triage'
    ? t(
        'settings.ai.agents.preset.triageHint',
        'Reads findings, comments and opens approval requests, and can also change status, severity and assignment like a person with that role.'
      )
    : t(
        'settings.ai.agents.preset.suggestHint',
        'Reads findings, comments and opens approval requests. It never changes a finding itself.'
      )
}

function reasonText(t: Translate, reason: string | undefined): string | undefined {
  switch (reason) {
    case 'no_active_owner':
      return t('settings.ai.agents.reason.noActiveOwner', 'No active accountable owner')
    case 'attestation_expired':
      return t('settings.ai.agents.reason.attestationExpired', 'Attestation overdue')
    case 'admin':
      return t('settings.ai.agents.reason.admin', 'Paused by an administrator')
    case 'no_permissions':
      return t('settings.ai.agents.reason.noPermissions', 'Missing permissions')
    default:
      return undefined
  }
}

function StatusPill({ aiAgent }: { aiAgent: AIAgent }) {
  const { t } = useTranslation()
  const reason = aiAgent.status === 'active' ? undefined : reasonText(t, aiAgent.pause_reason || '')
  if (aiAgent.status === 'active') {
    return <TonePill tone="success" label={t('settings.ai.agents.status.active', 'Active')} />
  }
  if (aiAgent.status === 'paused') {
    return (
      <TonePill
        tone="warning"
        label={t('settings.ai.agents.status.paused', 'Paused')}
        detail={reason}
      />
    )
  }
  return (
    <TonePill
      tone="muted"
      label={t('settings.ai.agents.status.disabled', 'Disabled')}
      detail={reason}
    />
  )
}

type Pending =
  { kind: 'action'; action: AIAgentAction; aiAgent: AIAgent } | { kind: 'delete'; aiAgent: AIAgent }

/**
 * Settings > AI > AI agents: the service accounts that take part in triage
 * like a person, each with accountable owners (API docs:
 * architecture/ai-analysis.md). Managing them needs `service_accounts:manage`;
 * an accountable owner may also attest and pause their own AI agent. The API
 * stays the authority.
 */
export function AIAgentsSection() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const userId = useAuthStore((s) => s.user?.id)
  const canManage = can(Permission.ServiceAccountsManage)
  const aiAgents = useAIAgents(true)

  const [createOpen, setCreateOpen] = useState(false)
  const [ownersFor, setOwnersFor] = useState<AIAgent | null>(null)
  const [presetFor, setPresetFor] = useState<AIAgent | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)

  const rows = aiAgents.data ?? []

  const actionsOf = (a: AIAgent): RowAction[] => {
    const isOwner = !!userId && a.owners.some((o) => o.kind === 'user' && o.id === userId)
    const out: RowAction[] = []
    if ((canManage || isOwner) && a.status !== 'disabled') {
      out.push({
        label: t('settings.ai.agents.action.attest', 'Attest'),
        onClick: () => setPending({ kind: 'action', action: 'attest', aiAgent: a }),
      })
    }
    if ((canManage || isOwner) && a.status === 'active') {
      out.push({
        label: t('settings.ai.agents.action.pause', 'Pause'),
        onClick: () => setPending({ kind: 'action', action: 'pause', aiAgent: a }),
      })
    }
    if (canManage) {
      if (a.status === 'paused') {
        out.push({
          label: t('settings.ai.agents.action.resume', 'Resume'),
          onClick: () => setPending({ kind: 'action', action: 'resume', aiAgent: a }),
        })
      }
      out.push(
        {
          label: t('settings.ai.agents.action.owners', 'Change owners'),
          onClick: () => setOwnersFor(a),
          separatorBefore: out.length > 0,
        },
        {
          label: t('settings.ai.agents.action.preset', 'Change preset'),
          onClick: () => setPresetFor(a),
        }
      )
      if (a.status !== 'disabled') {
        out.push({
          label: t('settings.ai.agents.action.disable', 'Disable'),
          onClick: () => setPending({ kind: 'action', action: 'disable', aiAgent: a }),
          separatorBefore: true,
        })
      }
      out.push({
        label: t('settings.ai.agents.action.delete', 'Delete'),
        destructive: true,
        onClick: () => setPending({ kind: 'delete', aiAgent: a }),
        separatorBefore: a.status === 'disabled',
      })
    }
    return out
  }

  const confirmPending = async () => {
    if (!pending) return
    try {
      if (pending.kind === 'delete') {
        await deleteAIAgent(pending.aiAgent.id)
        toast.success(t('settings.ai.agents.toast.deleted', 'AI agent deleted'))
      } else {
        await runAIAgentAction(pending.aiAgent.id, pending.action)
        toast.success(actionToast(t, pending.action))
      }
      await aiAgents.mutate()
      setPending(null)
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  return (
    <Card id="ai-agents">
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <Bot className="h-4 w-4" aria-hidden />
            {t('settings.ai.agents.title', 'AI agents')}
          </CardTitle>
          <CardDescription>
            {t(
              'settings.ai.agents.description',
              'An AI agent takes part in triage like a person, as its own service account. People or teams are accountable for it and must attest to it on a schedule; without an active owner it pauses.'
            )}
          </CardDescription>
        </div>
        {canManage && (
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="me-1 h-4 w-4" aria-hidden />
            {t('settings.ai.agents.create', 'New AI agent')}
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {aiAgents.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : aiAgents.error ? (
          <p className="text-sm text-destructive">{getErrorMessage(aiAgents.error)}</p>
        ) : rows.length === 0 ? (
          <EmptyState
            icon={Bot}
            title={t('settings.ai.agents.empty.title', 'No AI agents yet')}
            description={t(
              'settings.ai.agents.empty.description',
              'Create one to let AI help triage findings under the accountability of your people.'
            )}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('settings.ai.agents.col.name', 'Name')}</TableHead>
                <TableHead>{t('settings.ai.agents.col.preset', 'Preset')}</TableHead>
                <TableHead>{t('settings.ai.agents.col.status', 'Status')}</TableHead>
                <TableHead>{t('settings.ai.agents.col.owners', 'Accountable')}</TableHead>
                <TableHead>{t('settings.ai.agents.col.attestDue', 'Attest by')}</TableHead>
                <TableHead className="w-10">
                  <span className="sr-only">{t('settings.ai.agents.col.actions', 'Actions')}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((a) => (
                <TableRow key={a.id} data-testid="ai-agent-row">
                  <TableCell className="font-medium">{toDisplayText(a.name, 80)}</TableCell>
                  <TableCell>{presetName(t, a.preset)}</TableCell>
                  <TableCell>
                    <StatusPill aiAgent={a} />
                  </TableCell>
                  <TableCell>
                    {a.owners.map((o) => toDisplayText(o.name, 80)).join(', ') || '—'}
                  </TableCell>
                  <TableCell>{formatDateSafe(a.attest_due_at)}</TableCell>
                  <TableCell>
                    <DataTableRowActions
                      actions={actionsOf(a)}
                      label={t('settings.ai.agents.rowActions', 'Actions for {name}', {
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
          await aiAgents.mutate()
        }}
      />
      {ownersFor && (
        <OwnersDialog
          aiAgent={ownersFor}
          tenant={currentTenant?.slug}
          onClose={() => setOwnersFor(null)}
          onSaved={async () => {
            await aiAgents.mutate()
          }}
        />
      )}
      {presetFor && (
        <PresetDialog
          aiAgent={presetFor}
          onClose={() => setPresetFor(null)}
          onSaved={async () => {
            await aiAgents.mutate()
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

function actionOf(p: Pending): AIAgentAction | 'delete' {
  return p.kind === 'delete' ? 'delete' : p.action
}

function actionToast(t: Translate, a: AIAgentAction): string {
  switch (a) {
    case 'attest':
      return t('settings.ai.agents.toast.attest', 'Attestation recorded')
    case 'pause':
      return t('settings.ai.agents.toast.pause', 'AI agent paused')
    case 'resume':
      return t('settings.ai.agents.toast.resume', 'AI agent resumed')
    default:
      return t('settings.ai.agents.toast.disable', 'AI agent disabled')
  }
}

function confirmLabel(t: Translate, p: Pending): string {
  switch (actionOf(p)) {
    case 'attest':
      return t('settings.ai.agents.action.attest', 'Attest')
    case 'pause':
      return t('settings.ai.agents.action.pause', 'Pause')
    case 'resume':
      return t('settings.ai.agents.action.resume', 'Resume')
    case 'disable':
      return t('settings.ai.agents.action.disable', 'Disable')
    default:
      return t('settings.ai.agents.action.delete', 'Delete')
  }
}

function confirmTitle(t: Translate, p: Pending): string {
  const name = toDisplayText(p.aiAgent.name, 80)
  switch (actionOf(p)) {
    case 'attest':
      return t('settings.ai.agents.confirm.attestTitle', 'Attest to {name}?', { name })
    case 'pause':
      return t('settings.ai.agents.confirm.pauseTitle', 'Pause {name}?', { name })
    case 'resume':
      return t('settings.ai.agents.confirm.resumeTitle', 'Resume {name}?', { name })
    case 'disable':
      return t('settings.ai.agents.confirm.disableTitle', 'Disable {name}?', { name })
    default:
      return t('settings.ai.agents.confirm.deleteTitle', 'Delete {name}?', { name })
  }
}

function confirmDesc(t: Translate, p: Pending): string {
  switch (actionOf(p)) {
    case 'attest':
      return t(
        'settings.ai.agents.confirm.attestDesc',
        'You confirm that you are accountable for what this AI agent does and that its permissions are still right.'
      )
    case 'pause':
      return t(
        'settings.ai.agents.confirm.pauseDesc',
        'It stops acting on findings until it is resumed. Nothing it already did is undone.'
      )
    case 'resume':
      return t(
        'settings.ai.agents.confirm.resumeDesc',
        'It starts acting on findings again with its current preset and owners. This needs a recent sign-in.'
      )
    case 'disable':
      return t(
        'settings.ai.agents.confirm.disableDesc',
        'It stops acting and cannot be resumed until an administrator turns it back on. Its history stays.'
      )
    default:
      return t(
        'settings.ai.agents.confirm.deleteDesc',
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
  value: AIAgentPreset
  onChange: (v: AIAgentPreset) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1.5">
      <Select value={value} onValueChange={(v) => onChange(v as AIAgentPreset)} disabled={disabled}>
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
  const [preset, setPreset] = useState<AIAgentPreset>('suggest')
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
      await createAIAgent({
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        preset,
        owners,
      })
      toast.success(t('settings.ai.agents.toast.created', 'AI agent created'))
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
          <DialogTitle>{t('settings.ai.agents.createTitle', 'New AI agent')}</DialogTitle>
          <DialogDescription>
            {t(
              'settings.ai.agents.createDesc',
              'Creating an AI agent needs a recent sign-in. At least one accountable person or team is required.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="grid gap-4">
          <div className="space-y-1.5">
            <Label htmlFor="ai-agent-name">{t('settings.ai.agents.field.name', 'Name')}</Label>
            <Input
              id="ai-agent-name"
              value={name}
              maxLength={100}
              onChange={(e) => setName(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ai-agent-description">
              {t('settings.ai.agents.field.description', 'Description (optional)')}
            </Label>
            <Textarea
              id="ai-agent-description"
              value={description}
              maxLength={500}
              onChange={(e) => setDescription(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ai-agent-preset">
              {t('settings.ai.agents.field.preset', 'Preset')}
            </Label>
            <PresetSelect
              id="ai-agent-preset"
              value={preset}
              onChange={setPreset}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label>{t('settings.ai.agents.field.owners', 'Accountable owners')}</Label>
            <AIAgentOwnerPicker
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
            {t('settings.ai.agents.createSubmit', 'Create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function OwnersDialog({
  aiAgent,
  tenant,
  onClose,
  onSaved,
}: {
  aiAgent: AIAgent
  tenant: string | undefined
  onClose: () => void
  onSaved: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [owners, setOwners] = useState<AIOwnerInput[]>(
    aiAgent.owners.map((o) => ({ kind: o.kind, id: o.id }))
  )
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      await setAIAgentOwners(aiAgent.id, owners)
      toast.success(t('settings.ai.agents.toast.owners', 'Accountable owners updated'))
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
            {t('settings.ai.agents.ownersTitle', 'Accountable owners of {name}', {
              name: toDisplayText(aiAgent.name, 80),
            })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.ai.agents.ownersDesc',
              'These people and teams answer for what the AI agent does. At least one is required.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <AIAgentOwnerPicker tenant={tenant} value={owners} onChange={setOwners} disabled={busy} />
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={busy || owners.length === 0}>
            {t('settings.ai.agents.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function PresetDialog({
  aiAgent,
  onClose,
  onSaved,
}: {
  aiAgent: AIAgent
  onClose: () => void
  onSaved: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [preset, setPreset] = useState<AIAgentPreset>(aiAgent.preset)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      await setAIAgentPreset(aiAgent.id, preset)
      toast.success(t('settings.ai.agents.toast.preset', 'Preset updated'))
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
            {t('settings.ai.agents.presetTitle', 'Preset of {name}', {
              name: toDisplayText(aiAgent.name, 80),
            })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.ai.agents.presetDesc',
              'A wider preset needs an accountable person who holds its permissions. This needs a recent sign-in.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <PresetSelect
            id="ai-agent-preset-edit"
            value={preset}
            onChange={setPreset}
            disabled={busy}
          />
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={submit} disabled={busy || preset === aiAgent.preset}>
            {t('settings.ai.agents.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
