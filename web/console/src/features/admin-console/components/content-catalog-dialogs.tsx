'use client'

import { useId, useRef, useState } from 'react'
import { Upload } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { AdminConfirmDialog } from './admin-confirm-dialog'
import {
  importCatalogBundle,
  publishInstancePackage,
  revokeCatalogVersion,
  type ContentImportResult,
} from '../api/use-content-catalog'

/**
 * A file chooser in the console's language: the browser's own file control
 * labels itself in the browser's language ("Choose File / No file chosen"),
 * so the native input stays hidden behind a translated button and the chosen
 * file's name.
 */
function FileField({
  label,
  accept,
  file,
  onFile,
}: {
  label: string
  accept?: string
  file: File | null
  onFile: (f: File | null) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const input = useRef<HTMLInputElement>(null)
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="flex min-w-0 items-center gap-3">
        <Button type="button" variant="outline" onClick={() => input.current?.click()}>
          <Upload className="size-4" aria-hidden />
          {t('admin.catalog.chooseFile', 'Choose a file')}
        </Button>
        <span
          className="min-w-0 truncate text-body text-muted-foreground"
          title={file?.name}
          aria-live="polite"
        >
          {file ? file.name : t('admin.catalog.noFile', 'No file chosen')}
        </span>
      </div>
      <input
        ref={input}
        id={id}
        type="file"
        accept={accept}
        className="sr-only"
        tabIndex={-1}
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
    <AdminConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (!o) setFile(null)
        onOpenChange(o)
      }}
      title={t('admin.catalog.importTitle', 'Import a signed catalog bundle')}
      description={t(
        'admin.catalog.importDesc',
        'The bundle is verified against the trust roots set on the server (key set, signed index, revocation list, every package) before anything is stored. It changes what every organization can install.'
      )}
      confirmLabel={t('admin.catalog.import', 'Import')}
      reasonPlaceholder={t(
        'admin.catalog.reasonImport',
        'Monthly catalog update from the offline mirror, change 2231'
      )}
      requireCode
      canSubmit={!!file}
      onConfirm={async ({ reason, totp_code }) => {
        const r = await importCatalogBundle(file as File, reason, totp_code ?? '')
        setFile(null)
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
        file={file}
        onFile={setFile}
      />
    </AdminConfirmDialog>
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
  const clear = () => {
    setManifest(null)
    setArtifact(null)
    setAck(false)
  }
  return (
    <AdminConfirmDialog
      open={open}
      onOpenChange={(o) => {
        if (!o) clear()
        onOpenChange(o)
      }}
      title={t('admin.catalog.publishTitle', 'Publish an instance package')}
      description={t(
        'admin.catalog.publishDesc',
        'A package of this installation, offered to every organization next to the imported catalog. The manifest and artifact are checked like any package.'
      )}
      confirmLabel={t('admin.catalog.publish', 'Publish')}
      reasonPlaceholder={t(
        'admin.catalog.reasonPublish',
        'Our own login-page templates for every organization, change 2231'
      )}
      requireCode
      canSubmit={!!manifest && !!artifact}
      onConfirm={async ({ reason, totp_code }) => {
        const p = await publishInstancePackage({
          manifest: manifest as File,
          artifact: artifact as File,
          acknowledgeSecrets: ack,
          reason,
          totpCode: totp_code ?? '',
        })
        clear()
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
        file={manifest}
        onFile={setManifest}
      />
      <FileField
        label={t('admin.catalog.artifact', 'Artifact')}
        file={artifact}
        onFile={setArtifact}
      />
      <label htmlFor={ackId} className="flex items-start gap-2 text-sm">
        <Checkbox id={ackId} checked={ack} onCheckedChange={(v) => setAck(v === true)} />
        <span>
          {t(
            'admin.catalog.ackSecrets',
            'I checked the content: anything that looks like a secret in it is a placeholder or meant to be shared.'
          )}
        </span>
      </label>
    </AdminConfirmDialog>
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
    <AdminConfirmDialog
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
      confirmLabel={t('admin.catalog.revoke', 'Revoke')}
      reasonPlaceholder={t(
        'admin.catalog.reasonRevoke',
        'The publisher withdrew this version: its rules flood findings, advisory 2231'
      )}
      requireCode
      typeToConfirm={target?.version}
      canSubmit={!!target}
      onConfirm={async ({ reason, totp_code }) => {
        if (!target) return
        await revokeCatalogVersion(target.packageId, target.version, reason, totp_code ?? '')
        toast.success(t('admin.catalog.revoked', 'Version revoked'))
        onDone()
      }}
    />
  )
}
