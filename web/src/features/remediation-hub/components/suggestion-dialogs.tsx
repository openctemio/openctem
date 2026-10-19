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
import { memberLocation } from '../lib/suggestion-detail'
import { OwnerCombobox, type OwnerValue } from './owner-combobox'
import { TruncatedText } from '@/features/shared/components/truncated-text'

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
  const [overrides, setOverrides] = useState<Record<number, OwnerValue>>({})
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
      .filter(([, v]) => v.userId || v.groupId)
      .map(([k, v]) => ({
        index: Number(k),
        ...(v.userId ? { assignee_user_id: v.userId } : {}),
        ...(v.groupId ? { assignee_group_id: v.groupId } : {}),
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
                    {t('remediationHub.panel.taskN', undefined, { n: i + 1 })}
                    {' · '}
                    {t('remediationHub.suggestions.findingsCount', undefined, {
                      n: p.finding_ids.length,
                    })}
                  </span>
                  <div className="sm:col-span-2">
                    <OwnerCombobox
                      label={t('remediationHub.accept.ownerOf', undefined, { n: i + 1 })}
                      value={overrides[i] ?? { userId: p.owner_user_id, groupId: p.owner_group_id }}
                      suggested={
                        p.owner_rule === 'asset_owner'
                          ? { userId: p.owner_user_id, groupId: p.owner_group_id }
                          : undefined
                      }
                      onChange={(v) => setOverrides((o) => ({ ...o, [i]: v }))}
                      users={owners.users}
                      groups={owners.groups}
                      usersState={owners.usersState}
                      groupsState={owners.groupsState}
                    />
                  </div>
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
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm">{m.title}</p>
                      <TruncatedText
                        value={memberLocation(m).full}
                        middle={60}
                        className="text-muted-foreground block max-w-full font-mono text-xs"
                        label={t('remediationHub.panel.location')}
                      />
                      {m.active_task && (
                        <p className="text-warning text-xs">
                          {t('remediationHub.panel.claimed', undefined, {
                            title: m.active_task.title,
                          })}
                        </p>
                      )}
                    </div>
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

/** Days a snooze may last (the API allows at most 180). */
export const MAX_SNOOZE_DAYS = 180
const DAY_MS = 24 * 3600 * 1000

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10)
}

/** Snoozing until a chosen day (default a week); the suggestion comes back then. */
export function SnoozeDialog({
  suggestion,
  open,
  onOpenChange,
  onConfirm,
  busy,
}: {
  suggestion: RemediationSuggestion | null
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The end of the chosen day, as an ISO timestamp. */
  onConfirm: (until: string) => void
  busy?: boolean
}) {
  const { t } = useTranslation()
  // "Now" is read when the dialog opens, never during render.
  const [now, setNow] = useState(() => Date.now())
  const [date, setDate] = useState(() => isoDay(new Date(now + 7 * DAY_MS)))
  useEffect(() => {
    if (!open) return
    const at = Date.now()
    setNow(at)
    setDate(isoDay(new Date(at + 7 * DAY_MS)))
  }, [open])
  const min = isoDay(new Date(now + DAY_MS))
  const max = isoDay(new Date(now + (MAX_SNOOZE_DAYS - 1) * DAY_MS))
  const valid = date >= min && date <= max
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('remediationHub.snooze.title')}</DialogTitle>
          <DialogDescription>
            {t('remediationHub.snooze.description', undefined, { title: suggestion?.title ?? '' })}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-1">
          <Label htmlFor="snooze-until">{t('remediationHub.snooze.until')}</Label>
          <Input
            id="snooze-until"
            type="date"
            value={date}
            min={min}
            max={max}
            onChange={(e) => setDate(e.target.value)}
            aria-invalid={!valid}
          />
          <p className="text-muted-foreground text-xs">
            {t('remediationHub.snooze.hint', undefined, { days: MAX_SNOOZE_DAYS })}
          </p>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('remediationHub.actions.cancel')}
          </Button>
          <Button
            onClick={() => onConfirm(new Date(`${date}T23:59:59Z`).toISOString())}
            disabled={busy || !valid}
          >
            {t('remediationHub.actions.snooze')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
