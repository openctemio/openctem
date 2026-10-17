'use client'

import { useEffect, useState } from 'react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import {
  DENIABLE_ACTOR_KINDS,
  LIFECYCLE_PERMISSIONS,
  REQUIRED_FIELDS,
  type LifecycleCondition,
  type LifecycleGuard,
  type LifecycleTransition,
} from '../../api/use-finding-lifecycles'
import { LIFECYCLE_KEY_PATTERN, slugKey } from '../../lib/lifecycle'
import { ConditionEditor } from './condition-editor'

export interface PlaceOption {
  /** `status:<canonical>` or a sub-status id. */
  ref: string
  label: string
}

interface TransitionDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  transition?: LifecycleTransition
  places: PlaceOption[]
  /** Ids already used by other transitions of the draft. */
  takenIds: string[]
  onSave: (t: LifecycleTransition) => void
}

function toggle(list: string[], value: string, on: boolean): string[] {
  return on ? (list.includes(value) ? list : [...list, value]) : list.filter((v) => v !== value)
}

/**
 * One move of the draft: from where, to where, when it applies and what it
 * requires. Every guard only adds a constraint; the platform's rules
 * (permissions, four-eyes approval, evidence) still apply first.
 */
export function TransitionDialog({
  open,
  onOpenChange,
  transition,
  places,
  takenIds,
  onSave,
}: TransitionDialogProps) {
  const { t } = useTranslation()
  const [name, setName] = useState('')
  const [id, setId] = useState('')
  const [idTouched, setIdTouched] = useState(false)
  const [from, setFrom] = useState<string[]>([])
  const [to, setTo] = useState('')
  const [when, setWhen] = useState<LifecycleCondition[]>([])
  const [noteOn, setNoteOn] = useState(false)
  const [noteMin, setNoteMin] = useState(20)
  const [fields, setFields] = useState<string[]>([])
  const [perms, setPerms] = useState<string[]>([])
  const [kinds, setKinds] = useState<string[]>([])

  useEffect(() => {
    if (!open) return
    const g = (k: LifecycleGuard['kind']) => transition?.guards?.find((x) => x.kind === k)
    setName(transition?.name ?? '')
    setId(transition?.id ?? '')
    setIdTouched(!!transition)
    setFrom(transition?.from ?? [])
    setTo(transition?.to ?? '')
    setWhen(transition?.when ?? [])
    setNoteOn(!!g('require_note'))
    setNoteMin(g('require_note')?.min_len ?? 20)
    setFields(g('require_fields')?.fields ?? [])
    setPerms(g('require_permission')?.any_of ?? [])
    setKinds(g('deny_actor_kinds')?.kinds ?? [])
  }, [open, transition])

  const effectiveId = idTouched ? id : slugKey(name)
  const idValid = LIFECYCLE_KEY_PATTERN.test(effectiveId) && !takenIds.includes(effectiveId)
  const noteValid = !noteOn || (noteMin >= 1 && noteMin <= 500)
  const canSave = name.trim() !== '' && idValid && from.length > 0 && to !== '' && noteValid

  const save = () => {
    if (!canSave) return
    const guards: LifecycleGuard[] = []
    if (noteOn) guards.push({ kind: 'require_note', min_len: noteMin })
    if (fields.length) guards.push({ kind: 'require_fields', fields })
    if (perms.length) guards.push({ kind: 'require_permission', any_of: perms })
    if (kinds.length) guards.push({ kind: 'deny_actor_kinds', kinds })
    onSave({
      ...(transition ?? {}),
      id: effectiveId,
      name: name.trim(),
      from,
      to,
      when: when.length ? when : undefined,
      guards: guards.length ? guards : undefined,
    })
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {transition
              ? t('findingLifecycle.transition.editTitle', 'Edit move')
              : t('findingLifecycle.transition.addTitle', 'Add a move')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'findingLifecycle.transition.hint',
              'A move can only add requirements. Permissions, four-eyes approval and evidence rules still apply.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="transition-name">
                {t('findingLifecycle.transition.name', 'Name')}
              </Label>
              <Input
                id="transition-name"
                value={name}
                maxLength={64}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('findingLifecycle.transition.namePlaceholder', 'Send to review')}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="transition-id">{t('findingLifecycle.transition.id', 'Key')}</Label>
              <Input
                id="transition-id"
                className="font-mono"
                value={effectiveId}
                aria-invalid={effectiveId !== '' && !idValid}
                onChange={(e) => {
                  setIdTouched(true)
                  setId(e.target.value)
                }}
              />
              {takenIds.includes(effectiveId) && (
                <p className="text-xs text-destructive">
                  {t('findingLifecycle.transition.idTaken', 'Another move uses this key')}
                </p>
              )}
            </div>
          </div>

          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">
              {t('findingLifecycle.transition.from', 'From')}
            </legend>
            <div className="grid gap-1.5 sm:grid-cols-2">
              {places.map((p) => (
                <label key={p.ref} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={from.includes(p.ref)}
                    onCheckedChange={(v) => setFrom((cur) => toggle(cur, p.ref, v === true))}
                    aria-label={t('findingLifecycle.transition.fromPlace', 'From {place}', {
                      place: p.label,
                    })}
                  />
                  <span className="truncate">{p.label}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <div className="space-y-1.5">
            <Label htmlFor="transition-to">{t('findingLifecycle.transition.to', 'To')}</Label>
            <Select value={to} onValueChange={setTo}>
              <SelectTrigger id="transition-to" className="w-full sm:w-80">
                <SelectValue
                  placeholder={t('findingLifecycle.transition.pickTo', 'Choose where')}
                />
              </SelectTrigger>
              <SelectContent>
                {places.map((p) => (
                  <SelectItem key={p.ref} value={p.ref}>
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-medium">
              {t('findingLifecycle.transition.when', 'Applies when (optional)')}
            </h3>
            <p className="text-xs text-muted-foreground">
              {t(
                'findingLifecycle.transition.whenHint',
                'Without conditions the requirements apply to every finding.'
              )}
            </p>
            <ConditionEditor conditions={when} onChange={setWhen} idPrefix="transition-when" />
          </div>

          <div className="space-y-3">
            <h3 className="text-sm font-medium">
              {t('findingLifecycle.transition.requires', 'Requires')}
            </h3>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <label className="flex items-center gap-2">
                <Checkbox
                  checked={noteOn}
                  onCheckedChange={(v) => setNoteOn(v === true)}
                  aria-label={t('findingLifecycle.guard.note', 'A note of at least')}
                />
                {t('findingLifecycle.guard.note', 'A note of at least')}
              </label>
              <Input
                type="number"
                min={1}
                max={500}
                className="h-8 w-20"
                disabled={!noteOn}
                value={noteMin}
                aria-label={t('findingLifecycle.guard.noteMin', 'Shortest note')}
                onChange={(e) => setNoteMin(Number(e.target.value))}
              />
              <span>{t('findingLifecycle.guard.characters', 'characters')}</span>
            </div>

            <fieldset className="space-y-1.5">
              <legend className="text-xs font-medium text-muted-foreground">
                {t('findingLifecycle.guard.fields', 'Fields')}
              </legend>
              <div className="grid gap-1.5 sm:grid-cols-2">
                {REQUIRED_FIELDS.map((f) => (
                  <label key={f} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={fields.includes(f)}
                      onCheckedChange={(v) => setFields((cur) => toggle(cur, f, v === true))}
                    />
                    {t(`findingLifecycle.field.${f}`, f)}
                  </label>
                ))}
              </div>
            </fieldset>

            <fieldset className="space-y-1.5">
              <legend className="text-xs font-medium text-muted-foreground">
                {t('findingLifecycle.guard.permission', 'One of these permissions')}
              </legend>
              <div className="grid gap-1.5 sm:grid-cols-2">
                {LIFECYCLE_PERMISSIONS.map((p) => (
                  <label key={p} className="flex items-center gap-2 font-mono text-xs">
                    <Checkbox
                      checked={perms.includes(p)}
                      onCheckedChange={(v) => setPerms((cur) => toggle(cur, p, v === true))}
                    />
                    {p}
                  </label>
                ))}
              </div>
            </fieldset>

            <fieldset className="space-y-1.5">
              <legend className="text-xs font-medium text-muted-foreground">
                {t('findingLifecycle.guard.denyKinds', 'Not by')}
              </legend>
              <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                {DENIABLE_ACTOR_KINDS.map((k) => (
                  <label key={k} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={kinds.includes(k)}
                      onCheckedChange={(v) => setKinds((cur) => toggle(cur, k, v === true))}
                    />
                    {t(`findingLifecycle.actorKind.${k}`, k)}
                  </label>
                ))}
              </div>
            </fieldset>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={save} disabled={!canSave}>
            {t('findingLifecycle.transition.apply', 'Apply')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
