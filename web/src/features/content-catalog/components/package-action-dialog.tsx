'use client'

import { useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import type { ContentInstall, ContentOutcome, ContentPackageVersion } from '@/lib/api/generated'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
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
import { DetailCallout } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { installPackage, rollbackPackage, uninstallPackage, updatePackage } from '../api'
import { candidateVersions, needsLicenseAck, permissionDiff } from '../lib'
import { PermissionSummary } from './permission-summary'

export type PackageActionKind = 'install' | 'update' | 'rollback' | 'uninstall'

const NOTE_MAX = 500

interface Props {
  kind: PackageActionKind
  packageId: string
  versions: ContentPackageVersion[]
  install?: ContentInstall | null
  onOpenChange: (open: boolean) => void
  onDone: () => void
}

function defaultVersion(
  kind: PackageActionKind,
  choices: ContentPackageVersion[],
  install?: ContentInstall | null
): string {
  if (kind === 'rollback') {
    const prev = install?.previous?.version
    if (prev && choices.some((v) => v.version === prev)) return prev
  }
  return choices[0]?.version ?? ''
}

/** Install, update, roll back or uninstall one package; the API may file a request instead. */
export function PackageActionDialog({
  kind,
  packageId,
  versions,
  install,
  onOpenChange,
  onDone,
}: Props) {
  const { t } = useTranslation()
  const installed = install?.installed
  const choices = useMemo(() => {
    if (kind === 'install') return versions.filter((v) => !v.revoked)
    if (kind === 'update') return candidateVersions(versions, installed?.version, 'newer')
    if (kind === 'rollback') return candidateVersions(versions, installed?.version, 'older')
    return []
  }, [kind, versions, installed?.version])
  const [version, setVersion] = useState(() => defaultVersion(kind, choices, install))
  const [pinned, setPinned] = useState(false)
  const [ack, setAck] = useState(false)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const target = choices.find((v) => v.version === version)
  const ackNeeded = kind !== 'uninstall' && needsLicenseAck(target)
  const diff =
    kind === 'update' && target ? permissionDiff(installed?.permissions, target.permissions) : null
  const canSubmit = !busy && (kind === 'uninstall' || !!target) && (!ackNeeded || ack)

  const titles: Record<PackageActionKind, string> = {
    install: t('contentCatalog.action.installTitle', 'Install {id}', { id: packageId }),
    update: t('contentCatalog.action.updateTitle', 'Update {id}', { id: packageId }),
    rollback: t('contentCatalog.action.rollbackTitle', 'Roll back {id}', { id: packageId }),
    uninstall: t('contentCatalog.action.uninstallTitle', 'Uninstall {id}', { id: packageId }),
  }
  const descriptions: Record<PackageActionKind, string> = {
    install: t(
      'contentCatalog.action.installDesc',
      'Installs the version for the whole organization. A pinned installation does not follow automatic updates.'
    ),
    update: t(
      'contentCatalog.action.updateDesc',
      'Moves the installation to a newer version. Review what it asks for beyond the installed version.'
    ),
    rollback: t(
      'contentCatalog.action.rollbackDesc',
      'Moves the installation back to an older version and pins it, so automatic updates stop.'
    ),
    uninstall: t(
      'contentCatalog.action.uninstallDesc',
      'Removes the package from the organization. A package that another installed package depends on cannot be removed.'
    ),
  }
  const confirm: Record<PackageActionKind, string> = {
    install: t('contentCatalog.action.install', 'Install'),
    update: t('contentCatalog.action.update', 'Update'),
    rollback: t('contentCatalog.action.rollback', 'Roll back'),
    uninstall: t('contentCatalog.action.uninstall', 'Uninstall'),
  }

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      const trimmed = note.trim().slice(0, NOTE_MAX)
      let outcome: ContentOutcome | undefined
      if (kind === 'install') {
        outcome = await installPackage({
          package_id: packageId,
          version,
          pinned,
          acknowledge_license: ackNeeded && ack,
          note: trimmed,
        })
      } else if (kind === 'update') {
        outcome = await updatePackage(packageId, {
          version,
          acknowledge_license: ackNeeded && ack,
          note: trimmed,
        })
      } else if (kind === 'rollback') {
        outcome = await rollbackPackage(packageId, {
          version,
          acknowledge_license: ackNeeded && ack,
          note: trimmed,
        })
      } else {
        outcome = await uninstallPackage(packageId)
      }
      if (outcome?.request) {
        toast.success(t('contentCatalog.action.requested', 'Request sent for approval'), {
          description: t(
            'contentCatalog.action.requestedDesc',
            'Another member with the right to install content approves or rejects it under Requests.'
          ),
        })
      } else {
        toast.success(t('contentCatalog.action.done', 'Done: {action}', { action: confirm[kind] }))
      }
      onDone()
      onOpenChange(false)
    } catch (err) {
      setError(getErrorMessage(err, t('contentCatalog.error.generic', 'The change was refused.')))
    } finally {
      setBusy(false)
    }
  }

  const versionId = `content-action-version-${kind}`
  const noteId = `content-action-note-${kind}`
  const ackId = `content-action-ack-${kind}`
  const pinId = `content-action-pin-${kind}`

  return (
    <Dialog open onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size={kind === 'update' ? 'lg' : 'md'}>
        <DialogHeader>
          <DialogTitle className="break-all">{titles[kind]}</DialogTitle>
          <DialogDescription>{descriptions[kind]}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {kind !== 'uninstall' && (
            <div className="space-y-1.5">
              <Label htmlFor={versionId}>{t('contentCatalog.field.version', 'Version')}</Label>
              <Select value={version} onValueChange={setVersion}>
                <SelectTrigger id={versionId} className="w-full">
                  <SelectValue
                    placeholder={t('contentCatalog.field.pickVersion', 'Pick a version')}
                  />
                </SelectTrigger>
                <SelectContent>
                  {choices.map((v) => (
                    <SelectItem key={v.version} value={v.version ?? ''}>
                      {v.version}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {kind !== 'install' && installed?.version && (
                <p className="text-xs text-muted-foreground">
                  {t('contentCatalog.field.installedNow', 'Installed now: {version}', {
                    version: installed.version,
                  })}
                </p>
              )}
            </div>
          )}

          {diff && (
            <section className="space-y-2" aria-labelledby="content-diff-heading">
              <h3 id="content-diff-heading" className="text-sm font-semibold">
                {t('contentCatalog.diff.title', 'What this version asks for')}
              </h3>
              {diff.widens ? (
                <DetailCallout
                  tone="warning"
                  title={t(
                    'contentCatalog.diff.widens',
                    'This version asks for more than the installed one'
                  )}
                >
                  {t(
                    'contentCatalog.diff.widensHint',
                    'Highlighted fields are wider than in the installed version.'
                  )}
                </DetailCallout>
              ) : (
                <p className="text-sm text-muted-foreground">
                  {t(
                    'contentCatalog.diff.same',
                    'No wider permissions than the installed version.'
                  )}
                </p>
              )}
              <PermissionSummary permissions={target?.permissions} diff={diff} />
            </section>
          )}

          {kind === 'install' && (
            <div className="flex items-center justify-between gap-3">
              <Label htmlFor={pinId} className="flex flex-col items-start gap-0.5">
                <span>{t('contentCatalog.field.pin', 'Pin this version')}</span>
                <span className="text-xs font-normal text-muted-foreground">
                  {t(
                    'contentCatalog.field.pinHint',
                    'Automatic updates skip a pinned installation.'
                  )}
                </span>
              </Label>
              <Switch id={pinId} checked={pinned} onCheckedChange={setPinned} />
            </div>
          )}

          {ackNeeded && (
            <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-3">
              <Checkbox
                id={ackId}
                checked={ack}
                onCheckedChange={(c) => setAck(c === true)}
                className="mt-0.5"
              />
              <Label htmlFor={ackId} className="text-sm leading-snug font-normal">
                {t(
                  'contentCatalog.field.ack',
                  'Its license ({spdx}) does not allow use as a service. I confirm this organization may use it.',
                  { spdx: target?.license?.spdx ?? '-' }
                )}
              </Label>
            </div>
          )}

          {kind !== 'uninstall' && (
            <div className="space-y-1.5">
              <Label htmlFor={noteId}>{t('contentCatalog.field.note', 'Note (optional)')}</Label>
              <Textarea
                id={noteId}
                value={note}
                maxLength={NOTE_MAX}
                onChange={(e) => setNote(e.target.value)}
                rows={2}
              />
            </div>
          )}

          {error && (
            <p role="alert" className="text-sm break-words text-destructive">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('contentCatalog.cancel', 'Cancel')}
          </Button>
          <Button
            variant={kind === 'uninstall' ? 'destructive' : 'default'}
            onClick={() => void submit()}
            disabled={!canSubmit}
          >
            {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
            {confirm[kind]}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
