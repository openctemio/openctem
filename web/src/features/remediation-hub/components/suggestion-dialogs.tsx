'use client'

/**
 * Dismissing a suggestion (a reason is required) and accepting it after
 * edits (title, findings to leave out, owners, a deadline, auto-join).
 */

import type React from 'react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
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
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared'
import { DISMISS_REASONS, type DismissReason, type RemediationSuggestion } from '../api/types'
import { type ApproveBody, useSuggestionMembers } from '../api/use-remediation-hub'
import { useOwnerNames } from '../api/use-owner-names'
import { isTypingTarget } from '../lib/hub'

export function DismissDialog({
  suggestion,
  open,
  onOpenChange,
  onConfirm,
  busy,
}: {
  suggestion: RemediationSuggestion | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (reason: DismissReason, note: string) => void
  busy?: boolean
}) {
  const { t } = useTranslation()
  const [reason, setReason] = useState<DismissReason>('wrong_grouping')
  const [note, setNote] = useState('')
  useEffect(() => {
    if (open) {
      setReason('wrong_grouping')
      setNote('')
    }
  }, [open])
  const needsNote = reason === 'other' && note.trim() === ''
  // Number keys pick a reason (1 = the first), unless the person is typing.
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (isTypingTarget(e.target)) return
    const n = Number(e.key)
    if (Number.isInteger(n) && n >= 1 && n <= DISMISS_REASONS.length) {
      setReason(DISMISS_REASONS[n - 1])
      e.preventDefault()
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md" onKeyDown={onKeyDown}>
        <DialogHeader>
          <DialogTitle>{t('remediationHub.dismiss.title')}</DialogTitle>
          <DialogDescription>
            {t('remediationHub.dismiss.description', undefined, { title: suggestion?.title ?? '' })}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <RadioGroup
            value={reason}
            onValueChange={(v) => setReason(v as DismissReason)}
            aria-label={t('remediationHub.dismiss.reason')}
          >
            {DISMISS_REASONS.map((r, i) => (
              <div key={r} className="flex items-center gap-2">
                <RadioGroupItem id={`dismiss-${r}`} value={r} />
                <Label htmlFor={`dismiss-${r}`} className="font-normal">
                  <span className="text-muted-foreground me-1 font-mono text-xs">{i + 1}</span>
                  {t(`remediationHub.dismiss.reasons.${r}`)}
                </Label>
              </div>
            ))}
          </RadioGroup>
          <div className="space-y-1">
            <Label htmlFor="dismiss-note">{t('remediationHub.dismiss.note')}</Label>
            <Textarea
              id="dismiss-note"
              value={note}
              maxLength={500}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
          <p className="text-muted-foreground text-xs">{t('remediationHub.dismiss.memory')}</p>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('remediationHub.actions.cancel')}
          </Button>
          <Button onClick={() => onConfirm(reason, note.trim())} disabled={busy || needsNote}>
            {t('remediationHub.actions.dismiss')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

const NONE = '__none__'

export function AcceptDialog({
  suggestion,
  open,
  onOpenChange,
  onConfirm,
  busy,
  canAutoJoin,
}: {
  suggestion: RemediationSuggestion | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (body: Omit<ApproveBody, 'version'>) => void
  busy?: boolean
  /** The caller may turn auto-join on (no data-scope restriction). */
  canAutoJoin: boolean
}) {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  const [title, setTitle] = useState('')
  const [excluded, setExcluded] = useState<Set<string>>(new Set())
  const [overrides, setOverrides] = useState<Record<number, { user: string; group: string }>>({})
  const [deadline, setDeadline] = useState('')
  const [autoJoin, setAutoJoin] = useState(false)
  const [page, setPage] = useState(1)
  const { data: members } = useSuggestionMembers(open ? suggestion?.id : undefined, page, 50)

  useEffect(() => {
    if (open && suggestion) {
      setTitle(suggestion.title)
      setExcluded(new Set())
      setOverrides({})
      setDeadline('')
      setAutoJoin(false)
      setPage(1)
    }
  }, [open, suggestion])

  const exactKey = suggestion?.key_kind === 'upgrade' || suggestion?.key_kind === 'rotate'
  const remaining = (suggestion?.member_count ?? 0) - excluded.size
  const pages = members ? Math.max(1, Math.ceil(members.total / members.per_page)) : 1

  const body = useMemo((): Omit<ApproveBody, 'version'> => {
    const out: Omit<ApproveBody, 'version'> = {}
    if (suggestion && title.trim() && title.trim() !== suggestion.title) out.title = title.trim()
    if (excluded.size) out.exclude_finding_ids = [...excluded]
    const os = Object.entries(overrides)
      .filter(([, v]) => v.user || v.group)
      .map(([k, v]) => ({
        index: Number(k),
        ...(v.user ? { assignee_user_id: v.user } : {}),
        ...(v.group ? { assignee_group_id: v.group } : {}),
      }))
    if (os.length) out.owners = os
    if (deadline) out.deadline = deadline
    if (autoJoin) out.auto_join = true
    return out
  }, [suggestion, title, excluded, overrides, deadline, autoJoin])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('remediationHub.accept.title')}</DialogTitle>
          <DialogDescription>{t('remediationHub.accept.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          <div className="space-y-1">
            <Label htmlFor="accept-title">{t('remediationHub.accept.taskTitle')}</Label>
            <Input
              id="accept-title"
              value={title}
              maxLength={300}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
          {suggestion && suggestion.kind !== 'join' && suggestion.partitions.length > 0 && (
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('remediationHub.accept.owners')}</legend>
              {suggestion.partitions.map((p, i) => (
                <div key={i} className="grid gap-2 sm:grid-cols-[1fr_1fr_1fr] sm:items-center">
                  <span className="text-sm">
                    {t('remediationHub.accept.partition', undefined, {
                      n: i + 1,
                      findings: p.finding_ids.length,
                    })}
                  </span>
                  <Select
                    value={overrides[i]?.user || p.owner_user_id || NONE}
                    onValueChange={(v) =>
                      setOverrides((o) => ({
                        ...o,
                        [i]: {
                          user: v === NONE ? '' : v,
                          group: o[i]?.group ?? p.owner_group_id ?? '',
                        },
                      }))
                    }
                  >
                    <SelectTrigger aria-label={t('remediationHub.accept.user')}>
                      <SelectValue placeholder={t('remediationHub.accept.user')} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>{t('remediationHub.accept.noUser')}</SelectItem>
                      {owners.users.map((u) => (
                        <SelectItem key={u.id} value={u.id}>
                          {u.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select
                    value={overrides[i]?.group || p.owner_group_id || NONE}
                    onValueChange={(v) =>
                      setOverrides((o) => ({
                        ...o,
                        [i]: {
                          user: o[i]?.user ?? p.owner_user_id ?? '',
                          group: v === NONE ? '' : v,
                        },
                      }))
                    }
                  >
                    <SelectTrigger aria-label={t('remediationHub.accept.group')}>
                      <SelectValue placeholder={t('remediationHub.accept.group')} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>{t('remediationHub.accept.noGroup')}</SelectItem>
                      {owners.groups.map((g) => (
                        <SelectItem key={g.id} value={g.id}>
                          {g.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ))}
            </fieldset>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="accept-deadline">{t('remediationHub.accept.deadline')}</Label>
              <Input
                id="accept-deadline"
                type="date"
                value={deadline}
                onChange={(e) => setDeadline(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">
                {t('remediationHub.accept.deadlineHint')}
              </p>
            </div>
            {exactKey && canAutoJoin && (
              <div className="flex items-start gap-2 pt-6">
                <Checkbox
                  id="accept-autojoin"
                  checked={autoJoin}
                  onCheckedChange={(v) => setAutoJoin(v === true)}
                />
                <div>
                  <Label htmlFor="accept-autojoin">{t('remediationHub.accept.autoJoin')}</Label>
                  <p className="text-muted-foreground text-xs">
                    {t('remediationHub.accept.autoJoinHint')}
                  </p>
                </div>
              </div>
            )}
          </div>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">
              {t('remediationHub.accept.findings', undefined, {
                kept: remaining,
                total: suggestion?.member_count ?? 0,
              })}
            </legend>
            <p className="text-muted-foreground text-xs">
              {t('remediationHub.accept.excludeHint')}
            </p>
            <ul className="divide-y rounded-md border">
              {(members?.data ?? []).map((m) => {
                const kept = !excluded.has(m.finding_id)
                return (
                  <li key={m.finding_id} className="flex items-center gap-3 px-3 py-2">
                    <Checkbox
                      checked={kept}
                      onCheckedChange={(v) =>
                        setExcluded((s) => {
                          const n = new Set(s)
                          if (v === true) n.delete(m.finding_id)
                          else n.add(m.finding_id)
                          return n
                        })
                      }
                      aria-label={t('remediationHub.accept.keep', undefined, { title: m.title })}
                    />
                    <SeverityBadge severity={m.severity as Severity} />
                    <span className="min-w-0 flex-1 truncate text-sm">{m.title}</span>
                    <span className="text-muted-foreground hidden truncate text-xs sm:inline">
                      {m.asset_name}
                    </span>
                  </li>
                )
              })}
            </ul>
            {pages > 1 && (
              <div className="flex items-center justify-end gap-2 text-xs">
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  {t('remediationHub.actions.previous')}
                </Button>
                <span>{t('remediationHub.pageOf', undefined, { page, pages })}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={page >= pages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  {t('remediationHub.actions.next')}
                </Button>
              </div>
            )}
          </fieldset>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('remediationHub.actions.cancel')}
          </Button>
          <Button
            onClick={() => onConfirm(body)}
            disabled={busy || remaining <= 0 || !title.trim()}
          >
            {t('remediationHub.accept.confirm', undefined, { n: remaining })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
