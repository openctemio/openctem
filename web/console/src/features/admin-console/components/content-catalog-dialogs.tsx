'use client'

import { useId, useState, type FormEvent, type ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import {
  importCatalogBundle,
  publishInstancePackage,
  revokeCatalogVersion,
  type ContentImportResult,
} from '../api/use-content-catalog'

const REASON_MAX = 500

/** A dialog that runs one guarded catalog action with a reason. */
function ReasonActionDialog({
  open,
  onOpenChange,
  title,
  description,
  confirm,
  destructive,
  ready,
  run,
  children,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  title: string
  description: string
  confirm: string
  destructive?: boolean
  ready: boolean
  run: (reason: string) => Promise<void>
  children?: ReactNode
}) {
  const { t } = useTranslation()
  const reasonId = useId()
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await run(reason.trim())
      setReason('')
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('admin.catalog.failed', 'The action failed'))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent size="md">
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            {children}
            <div className="grid gap-1.5">
              <Label htmlFor={reasonId}>{t('admin.catalog.reason', 'Reason')}</Label>
              <Textarea
                id={reasonId}
                value={reason}
                rows={2}
                maxLength={REASON_MAX}
                onChange={(e) => setReason(e.target.value)}
                placeholder={t('admin.catalog.reasonHint', 'Recorded in the admin audit log.')}
              />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={busy}
            >
              {t('admin.catalog.cancel', 'Cancel')}
            </Button>
            <Button
              type="submit"
              variant={destructive ? 'destructive' : 'default'}
              disabled={busy || !ready || reason.trim() === ''}
            >
              {busy && <Loader2 className="me-1.5 size-4 animate-spin" />}
              {confirm}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}

function FileField({
  label,
  accept,
  onFile,
}: {
  label: string
  accept?: string
  onFile: (f: File | null) => void
}) {
  const id = useId()
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type="file"
        accept={accept}
        onChange={(e) => onFile(e.target.files?.[0] ?? null)}
      />
    </div>
  )
}

/** Import a signed catalog bundle (offline update of the instance catalog). */
export function ImportBundleDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onDone: (r: ContentImportResult) => void
}) {
  const { t } = useTranslation()
  const [file, setFile] = useState<File | null>(null)
  return (
    <ReasonActionDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('admin.catalog.importTitle', 'Import a signed catalog bundle')}
      description={t(
        'admin.catalog.importDesc',
        'The bundle is verified against the trust roots set on the server (key set, signed index, revocation list, every package) before anything is stored. It changes what every organization can install.'
      )}
      confirm={t('admin.catalog.import', 'Import')}
      ready={!!file}
      run={async (reason) => {
        const r = await importCatalogBundle(file as File, reason)
        toast.success(
          r.unchanged
            ? t('admin.catalog.importUnchanged', 'Nothing new: this bundle was already imported')
            : t('admin.catalog.imported', '{added} packages added, {revoked} versions revoked', {
                added: r.added,
                revoked: r.revoked_versions,
              })
        )
        onDone(r)
      }}
    >
      <FileField
        label={t('admin.catalog.bundle', 'Bundle (tar or tar.gz)')}
        accept=".tar,.gz,.tgz,application/gzip,application/x-tar"
        onFile={setFile}
      />
    </ReasonActionDialog>
  )
}

/** Publish an instance package (this installation's own package). */
export function PublishPackageDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onDone: () => void
}) {
  const { t } = useTranslation()
  const ackId = useId()
  const [manifest, setManifest] = useState<File | null>(null)
  const [artifact, setArtifact] = useState<File | null>(null)
  const [ack, setAck] = useState(false)
  return (
    <ReasonActionDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('admin.catalog.publishTitle', 'Publish an instance package')}
      description={t(
        'admin.catalog.publishDesc',
        'A package of this installation, offered to every organization next to the imported catalog. The manifest and artifact are checked like any package.'
      )}
      confirm={t('admin.catalog.publish', 'Publish')}
      ready={!!manifest && !!artifact}
      run={async (reason) => {
        const p = await publishInstancePackage({
          manifest: manifest as File,
          artifact: artifact as File,
          acknowledgeSecrets: ack,
          reason,
        })
        toast.success(
          t('admin.catalog.published', '{id} {version} published', {
            id: p.package_id,
            version: p.version,
          })
        )
        onDone()
      }}
    >
      <FileField
        label={t('admin.catalog.manifest', 'Manifest (package.yaml)')}
        accept=".yaml,.yml"
        onFile={setManifest}
      />
      <FileField label={t('admin.catalog.artifact', 'Artifact')} onFile={setArtifact} />
      <label htmlFor={ackId} className="flex items-start gap-2 text-sm">
        <Checkbox id={ackId} checked={ack} onCheckedChange={(v) => setAck(v === true)} />
        <span>
          {t(
            'admin.catalog.ackSecrets',
            'I checked the content: anything that looks like a secret in it is a placeholder or meant to be shared.'
          )}
        </span>
      </label>
    </ReasonActionDialog>
  )
}

/** Revoke one version of an instance catalog package. */
export function RevokeVersionDialog({
  target,
  onOpenChange,
  onDone,
}: {
  target: { packageId: string; version: string } | null
  onOpenChange: (o: boolean) => void
  onDone: () => void
}) {
  const { t } = useTranslation()
  return (
    <ReasonActionDialog
      open={!!target}
      onOpenChange={onOpenChange}
      destructive
      title={t('admin.catalog.revokeTitle', 'Revoke {id} {version}?', {
        id: target?.packageId ?? '',
        version: target?.version ?? '',
      })}
      description={t(
        'admin.catalog.revokeDesc',
        'Every organization’s installation of this version becomes revoked and stops being delivered to its sensors. This cannot be undone.'
      )}
      confirm={t('admin.catalog.revoke', 'Revoke')}
      ready={!!target}
      run={async (reason) => {
        if (!target) return
        await revokeCatalogVersion(target.packageId, target.version, reason)
        toast.success(t('admin.catalog.revoked', 'Version revoked'))
        onDone()
      }}
    />
  )
}
