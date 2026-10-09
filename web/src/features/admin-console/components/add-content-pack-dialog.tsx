'use client'

import { useId, useState, type FormEvent } from 'react'
import { Loader2, Upload } from 'lucide-react'
import { toast } from 'sonner'
import type { ContentLintReport } from '@/lib/api/generated'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { Textarea } from '@/components/ui/textarea'
import { AdminApiError } from '../api/admin-client'
import { REASON_MAX, REASON_MIN, stepUpErrorMessage } from './admin-confirm-dialog'
import { importContentPack, uploadContentPack } from '../api/use-content-packs'
import { ContentLintReportView, asLintReport } from './content-lint-report'

export const KNOWN_KINDS = ['nuclei-templates', 'semgrep-rules', 'wordlist'] as const
const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/
const KIND_RE = /^([a-z][a-z0-9-]{1,40}|x-[a-z0-9-]{1,32}\/[a-z][a-z0-9-]{1,40})$/
export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/

/** The form's problems, the API's own rules (null when it can be sent). */
export function contentPackFormProblem(f: {
  mode: 'upload' | 'import'
  name: string
  version: string
  kind: string
  file?: File | null
  url?: string
  digest?: string
}): string | null {
  if (!NAME_RE.test(f.name)) return 'Name: lowercase letters, digits, dot, dash or underscore.'
  if (!VERSION_RE.test(f.version)) return 'Version: letters, digits and . _ + -'
  if (!KIND_RE.test(f.kind)) return 'Kind: a known kind or x-<namespace>/<kind>.'
  if (f.mode === 'upload' && !f.file) return 'Choose a tar or tar.gz archive.'
  if (f.mode === 'import') {
    if (!/^https:\/\/\S+$/.test(f.url ?? '')) return 'The URL must start with https://'
    if (!DIGEST_RE.test(f.digest ?? ''))
      return 'Digest: sha256: followed by 64 lowercase hex characters.'
  }
  return null
}

/**
 * Add a platform content pack: upload an archive or import a release by https
 * URL pinned to its sha256. A refusal shows the lint report; suspected secrets
 * need an explicit acknowledgement before the pack is sent again.
 */
export function AddContentPackDialog({ onAdded }: { onAdded: () => void }) {
  const { t } = useTranslation()
  const id = {
    name: useId(),
    version: useId(),
    kind: useId(),
    file: useId(),
    url: useId(),
    digest: useId(),
    ack: useId(),
    reason: useId(),
    code: useId(),
  }
  const [open, setOpen] = useState(false)
  const [mode, setMode] = useState<'upload' | 'import'>('upload')
  const [name, setName] = useState('')
  const [version, setVersion] = useState('')
  const [kind, setKind] = useState<string>('nuclei-templates')
  const [file, setFile] = useState<File | null>(null)
  const [url, setUrl] = useState('')
  const [digest, setDigest] = useState('')
  const [report, setReport] = useState<ContentLintReport | null>(null)
  const [secretsFound, setSecretsFound] = useState(false)
  const [ack, setAck] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [reason, setReason] = useState('')
  const [code, setCode] = useState('')
  const proofOk =
    reason.trim().length >= REASON_MIN && reason.trim().length <= REASON_MAX && /^\d{6}$/.test(code)

  const problem = contentPackFormProblem({ mode, name, version, kind, file, url, digest })
  const blockedBySecrets = secretsFound && !ack

  const reset = () => {
    setName('')
    setVersion('')
    setFile(null)
    setUrl('')
    setDigest('')
    setReport(null)
    setSecretsFound(false)
    setAck(false)
    setError(null)
    setBusy(false)
    setReason('')
    setCode('')
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (problem || blockedBySecrets || !proofOk) return
    setBusy(true)
    setError(null)
    try {
      const pack =
        mode === 'upload'
          ? await uploadContentPack({
              name,
              version,
              kind,
              archive: file as File,
              acknowledgeSecrets: ack,
              reason: reason.trim(),
              totpCode: code,
            })
          : await importContentPack({
              name,
              version,
              kind,
              url,
              digest,
              acknowledge_secrets: ack,
              reason: reason.trim(),
              totp_code: code,
            })
      const excluded = pack.lint?.excluded ?? 0
      toast.success(
        excluded > 0
          ? t(
              'admin.cp.addedExcluded',
              'Pack added; {count} file(s) were left out (see its warnings).',
              {
                count: excluded,
              }
            )
          : t('admin.cp.added', 'Pack added and signed.')
      )
      reset()
      setOpen(false)
      onAdded()
    } catch (err) {
      setBusy(false)
      // A code is single use: the next attempt needs a new one.
      setCode('')
      if (err instanceof AdminApiError) {
        setReport(asLintReport(err.details))
        if (err.code === 'CONTENT_SECRETS_FOUND') {
          setSecretsFound(true)
          setAck(false)
        }
      }
      setError(stepUpErrorMessage(err, t))
    }
  }

  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)}>
        <Upload className="me-2 size-4" />
        {t('admin.cp.add', 'Add pack')}
      </Button>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) reset()
          setOpen(next)
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <form onSubmit={submit} className="space-y-4">
            <DialogHeader>
              <DialogTitle>{t('admin.cp.addTitle', 'Add a content pack')}</DialogTitle>
              <DialogDescription>
                {t(
                  'admin.cp.addWhat',
                  'The platform lints the files, leaves out the ones that fail, classifies the pack and signs it. Sensors only run signed packs.'
                )}
              </DialogDescription>
            </DialogHeader>
            <Tabs value={mode} onValueChange={(v) => setMode(v as 'upload' | 'import')}>
              <TabsList>
                <TabsTrigger value="upload">
                  {t('admin.cp.modeUpload', 'Upload an archive')}
                </TabsTrigger>
                <TabsTrigger value="import">
                  {t('admin.cp.modeImport', 'Import from a URL')}
                </TabsTrigger>
              </TabsList>
            </Tabs>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label htmlFor={id.name}>{t('admin.cp.name', 'Name')}</Label>
                <Input
                  id={id.name}
                  value={name}
                  onChange={(e) => setName(e.target.value.trim())}
                  placeholder="nuclei-core"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={id.version}>{t('admin.cp.version', 'Version')}</Label>
                <Input
                  id={id.version}
                  value={version}
                  onChange={(e) => setVersion(e.target.value.trim())}
                  placeholder="10.2.4"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={id.kind}>{t('admin.cp.kind', 'Kind')}</Label>
                <Input
                  id={id.kind}
                  list={`${id.kind}-list`}
                  value={kind}
                  onChange={(e) => setKind(e.target.value.trim())}
                />
                <datalist id={`${id.kind}-list`}>
                  {KNOWN_KINDS.map((k) => (
                    <option key={k} value={k} />
                  ))}
                </datalist>
              </div>
            </div>
            {mode === 'upload' ? (
              <div className="space-y-1.5">
                <Label htmlFor={id.file}>
                  {t('admin.cp.archive', 'Archive (tar or tar.gz, up to 128 MiB)')}
                </Label>
                <Input
                  id={id.file}
                  type="file"
                  accept=".tar,.tgz,.tar.gz,application/gzip,application/x-tar"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
              </div>
            ) : (
              <div className="grid gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor={id.url}>{t('admin.cp.url', 'Release URL (https)')}</Label>
                  <Input
                    id={id.url}
                    value={url}
                    onChange={(e) => setUrl(e.target.value.trim())}
                    placeholder="https://"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={id.digest}>{t('admin.cp.digest', 'Expected digest')}</Label>
                  <Input
                    id={id.digest}
                    value={digest}
                    onChange={(e) => setDigest(e.target.value.trim().toLowerCase())}
                    placeholder="sha256:"
                    className="font-mono text-xs"
                  />
                </div>
              </div>
            )}
            <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
              <div className="space-y-1.5">
                <Label htmlFor={id.reason}>{t('admin.confirm.reason', 'Reason')}</Label>
                <Textarea
                  id={id.reason}
                  rows={2}
                  maxLength={REASON_MAX}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={t(
                    'admin.cp.reasonPlaceholder',
                    'Why, e.g. "monthly template refresh, change 912"'
                  )}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={id.code}>
                  {t('admin.confirm.code', 'Code from your authenticator')}
                </Label>
                <Input
                  id={id.code}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  className="w-36 font-mono tracking-widest"
                />
              </div>
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {report && <ContentLintReportView report={report} />}
            {secretsFound && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/40 p-3">
                <Checkbox id={id.ack} checked={ack} onCheckedChange={(v) => setAck(v === true)} />
                <Label htmlFor={id.ack} className="text-sm leading-snug font-normal">
                  {t(
                    'admin.cp.ackSecrets',
                    'I checked every file listed above: these are not real credentials (or must ship as is). Store the pack anyway.'
                  )}
                </Label>
              </div>
            )}
            {problem && (name || version || file || url) && (
              <p className="text-sm text-muted-foreground">{problem}</p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button
                type="submit"
                disabled={busy || problem !== null || blockedBySecrets || !proofOk}
              >
                {busy && <Loader2 className="me-2 size-4 animate-spin" />}
                {secretsFound
                  ? t('admin.cp.sendAgain', 'Send again with acknowledgement')
                  : mode === 'upload'
                    ? t('admin.cp.upload', 'Upload and sign')
                    : t('admin.cp.import', 'Import and sign')}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}
