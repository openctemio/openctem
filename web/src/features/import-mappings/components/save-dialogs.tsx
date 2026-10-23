'use client'

import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import type { IdentityChange } from '../api/import-mappings-api'
import { MAPPING_NAME_RE } from '../lib/targets'

function ErrorList({ errors }: { errors: string[] }) {
  if (errors.length === 0) return null
  return (
    <ul
      className="mt-3 list-disc rounded-md border border-destructive/50 bg-destructive/5 p-3 ps-7 text-sm"
      role="alert"
    >
      {errors.map((e, i) => (
        <li key={i} className="break-words">
          {e}
        </li>
      ))}
    </ul>
  )
}

/** Name, description and first version note of a new mapping. */
export function CreateMappingDialog({
  open,
  onOpenChange,
  onSubmit,
  busy,
  errors,
  initialName = '',
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (input: { name: string; description: string; note: string }) => void
  busy: boolean
  errors: string[]
  initialName?: string
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(initialName)
  const [description, setDescription] = useState('')
  const [note, setNote] = useState('')
  useEffect(() => {
    if (open) setName((n) => n || initialName)
  }, [open, initialName])
  const nameOk = MAPPING_NAME_RE.test(name)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('importMappings.create.title', 'Save the mapping')}</DialogTitle>
          <DialogDescription>
            {t(
              'importMappings.create.description',
              'Imports choose it by name. Findings it imports record the source as mapped:<name>.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id="im-create"
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (nameOk && !busy) onSubmit({ name, description, note })
            }}
          >
            <div className="grid gap-1.5">
              <Label htmlFor="im-name">{t('importMappings.create.name', 'Name')}</Label>
              <Input
                id="im-name"
                value={name}
                maxLength={64}
                autoComplete="off"
                className="font-mono"
                placeholder="vendor-export"
                aria-invalid={name !== '' && !nameOk}
                onChange={(e) => setName(e.target.value.trim())}
              />
              <p className="text-xs text-muted-foreground">
                {t(
                  'importMappings.create.nameHelp',
                  'Lower-case letters, digits, dot, dash and underscore; starts with a letter or digit; at most 64.'
                )}
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="im-desc">
                {t('importMappings.create.descriptionLabel', 'Description')}
              </Label>
              <Textarea
                id="im-desc"
                rows={2}
                maxLength={1000}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="im-note">{t('importMappings.save.note', 'Version note')}</Label>
              <Input
                id="im-note"
                value={note}
                maxLength={500}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
          </form>
          <ErrorList errors={errors} />
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('importMappings.common.cancel', 'Cancel')}
          </Button>
          <Button type="submit" form="im-create" disabled={!nameOk || busy}>
            {t('importMappings.create.submit', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The note of a new version. */
export function SaveVersionDialog({
  open,
  onOpenChange,
  onSubmit,
  busy,
  errors,
  nextVersion,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (note: string) => void
  busy: boolean
  errors: string[]
  nextVersion: number
}) {
  const { t } = useTranslation()
  const [note, setNote] = useState('')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {t('importMappings.save.title', 'Save as version {v}', { v: nextVersion })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'importMappings.save.description',
              'Imports that name the mapping without a version use the new version. Earlier versions stay available.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id="im-version"
            onSubmit={(e) => {
              e.preventDefault()
              if (!busy) onSubmit(note)
            }}
          >
            <Label htmlFor="im-vnote">{t('importMappings.save.note', 'Version note')}</Label>
            <Input
              id="im-vnote"
              className="mt-1.5"
              value={note}
              maxLength={500}
              onChange={(e) => setNote(e.target.value)}
            />
          </form>
          <ErrorList errors={errors} />
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('importMappings.common.cancel', 'Cancel')}
          </Button>
          <Button type="submit" form="im-version" disabled={busy}>
            {t('importMappings.save.submit', 'Save version')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function IdentityList({ items }: { items: string[] }) {
  const { t } = useTranslation()
  if (items.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">{t('importMappings.identity.none', 'none')}</p>
    )
  }
  return (
    <ul className="flex flex-wrap gap-1">
      {items.map((i) => (
        <li key={i}>
          <code className="rounded border px-1.5 py-0.5 text-xs">{i}</code>
        </li>
      ))}
    </ul>
  )
}

/**
 * The API refused a version whose identity members or their values changed:
 * the person confirms that new findings will not match earlier ones.
 */
export function IdentityConfirmDialog({
  change,
  onCancel,
  onConfirm,
  busy,
}: {
  change: IdentityChange | null
  onCancel: () => void
  onConfirm: () => void
  busy: boolean
}) {
  const { t } = useTranslation()
  return (
    <Dialog open={change !== null} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {t('importMappings.identity.title', 'Change how findings are identified?')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'importMappings.identity.description',
              'This version identifies findings differently. Findings imported with earlier versions will not match the ones this version imports: the same issue comes in as a new finding. Earlier findings stay as they are; an operator can re-key them with the refingerprint tool.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {change && (
            <div className="grid gap-3">
              <div className="grid gap-1">
                <p className="text-xs font-medium text-muted-foreground">
                  {t('importMappings.identity.previous', 'Identity until now')}
                </p>
                <IdentityList items={change.previous} />
              </div>
              <div className="grid gap-1">
                <p className="text-xs font-medium text-muted-foreground">
                  {t('importMappings.identity.next', 'Identity of this version')}
                </p>
                <IdentityList items={change.next} />
              </div>
              {change.previous.join('\n') === change.next.join('\n') && (
                <p className="text-sm text-muted-foreground">
                  {t(
                    'importMappings.identity.sameMembers',
                    'The members are the same, but the values they are read from changed.'
                  )}
                </p>
              )}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>
            {t('importMappings.common.cancel', 'Cancel')}
          </Button>
          <Button variant="destructive" onClick={onConfirm} disabled={busy}>
            {t('importMappings.identity.confirm', 'Save with the new identity')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Rename a mapping or change its description. */
export function EditDetailsDialog({
  open,
  onOpenChange,
  name: initialName,
  description: initialDescription,
  onSubmit,
  busy,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  name: string
  description: string
  onSubmit: (input: { name?: string; description?: string }) => void
  busy: boolean
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(initialName)
  const [description, setDescription] = useState(initialDescription)
  useEffect(() => {
    if (open) {
      setName(initialName)
      setDescription(initialDescription)
    }
  }, [open, initialName, initialDescription])
  const nameOk = MAPPING_NAME_RE.test(name)
  const changed = name !== initialName || description !== initialDescription

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('importMappings.details.title', 'Name and description')}</DialogTitle>
          <DialogDescription>
            {t(
              'importMappings.details.description',
              'Renaming changes the name imports use (format mapping:<name>) and the source recorded on findings imported from now on.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id="im-details"
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (!nameOk || !changed || busy) return
              onSubmit({
                ...(name !== initialName ? { name } : {}),
                ...(description !== initialDescription ? { description } : {}),
              })
            }}
          >
            <div className="grid gap-1.5">
              <Label htmlFor="im-rename">{t('importMappings.create.name', 'Name')}</Label>
              <Input
                id="im-rename"
                className="font-mono"
                value={name}
                maxLength={64}
                aria-invalid={!nameOk}
                onChange={(e) => setName(e.target.value.trim())}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="im-redesc">
                {t('importMappings.create.descriptionLabel', 'Description')}
              </Label>
              <Textarea
                id="im-redesc"
                rows={2}
                maxLength={1000}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
          </form>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('importMappings.common.cancel', 'Cancel')}
          </Button>
          <Button type="submit" form="im-details" disabled={!nameOk || !changed || busy}>
            {t('importMappings.details.submit', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
