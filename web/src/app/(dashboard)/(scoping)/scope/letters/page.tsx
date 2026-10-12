'use client'

/**
 * Scoping › Scope › Letters (RFC-065 §13): the organization's letters of
 * authorization. Uploading a letter authorizes nothing by itself; scope
 * entries naming it (authorization source "letter of authorization") go
 * through the approval policy and authorize only while it is valid. A
 * revoked or expired letter stops every entry naming it.
 */

import { useId, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Download, FileSignature, Loader2, Upload } from 'lucide-react'
import { Main } from '@/components/layout'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { SCOPE_SECTION_TABS } from '@/config/section-tabs'
import { ApiClientError } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import { EmptyState, ErrorState, GatedSectionTabs, PageHeader } from '@/features/shared'
import {
  LETTER_PROBLEM_TEXT,
  LETTER_TYPES,
  daysLeft,
  downloadLetter,
  letterFormProblem,
  revokeLetter,
  uploadLetter,
  useLetters,
  type AuthorizationLetter,
} from '@/features/scope-letters'

function errorText(err: unknown, fallback: string): string {
  return err instanceof ApiClientError ? err.message : fallback
}

function LetterStatus({ letter }: { letter: AuthorizationLetter }) {
  const { t } = useTranslation()
  if (letter.revoked_at) {
    return <Badge variant="secondary">{t('letters.status.revoked', 'Revoked')}</Badge>
  }
  if (!letter.in_effect) {
    const ended = daysLeft(letter.valid_until) <= 0
    return (
      <Badge variant="secondary">
        {ended
          ? t('letters.status.expired', 'Expired')
          : t('letters.status.notYet', 'Not yet valid')}
      </Badge>
    )
  }
  const left = daysLeft(letter.valid_until)
  return (
    <Badge variant={left <= 30 ? 'outline' : 'default'}>
      {left <= 30
        ? t('letters.status.endsSoon', 'Ends in {days} days', { days: left })
        : t('letters.status.inEffect', 'In effect')}
    </Badge>
  )
}

function UploadForm({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation()
  const id = useId()
  const [file, setFile] = useState<File | null>(null)
  const [title, setTitle] = useState('')
  const [issuer, setIssuer] = useState('')
  const [reference, setReference] = useState('')
  const [validFrom, setValidFrom] = useState('')
  const [validUntil, setValidUntil] = useState('')
  const [busy, setBusy] = useState(false)

  const problem = useMemo(
    () => letterFormProblem({ file, title, validFrom, validUntil }),
    [file, title, validFrom, validUntil]
  )

  const submit = async () => {
    if (!file || problem) return
    setBusy(true)
    try {
      await uploadLetter({ file, title: title.trim(), issuer, reference, validFrom, validUntil })
      toast.success(t('letters.uploaded', 'Letter uploaded'))
      onDone()
    } catch (err) {
      toast.error(errorText(err, t('letters.uploadFailed', 'The upload failed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="grid gap-4 rounded-md border p-4 sm:grid-cols-2">
      <div className="space-y-2 sm:col-span-2">
        <Label htmlFor={`${id}-file`}>{t('letters.form.file', 'Signed letter')}</Label>
        <Input
          id={`${id}-file`}
          type="file"
          accept={LETTER_TYPES.join(',')}
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor={`${id}-title`}>{t('letters.form.title', 'Title')}</Label>
        <Input
          id={`${id}-title`}
          value={title}
          maxLength={200}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor={`${id}-issuer`}>
          {t('letters.form.issuer', 'Issued by (who signed it)')}
        </Label>
        <Input
          id={`${id}-issuer`}
          value={issuer}
          maxLength={200}
          onChange={(e) => setIssuer(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor={`${id}-from`}>{t('letters.form.from', 'Valid from')}</Label>
        <Input
          id={`${id}-from`}
          type="date"
          value={validFrom}
          onChange={(e) => setValidFrom(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor={`${id}-until`}>{t('letters.form.until', 'Valid until')}</Label>
        <Input
          id={`${id}-until`}
          type="date"
          value={validUntil}
          onChange={(e) => setValidUntil(e.target.value)}
        />
      </div>
      <div className="space-y-2 sm:col-span-2">
        <Label htmlFor={`${id}-ref`}>
          {t('letters.form.reference', 'Reference (contract or engagement, optional)')}
        </Label>
        <Input
          id={`${id}-ref`}
          value={reference}
          maxLength={200}
          onChange={(e) => setReference(e.target.value)}
        />
      </div>
      <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
        <Button onClick={submit} disabled={busy || problem !== null}>
          {busy ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Upload className="mr-2 h-4 w-4" />
          )}
          {t('letters.upload', 'Upload letter')}
        </Button>
        {problem && (file || title || validFrom || validUntil) && (
          <p className="text-muted-foreground text-xs">
            {t(`letters.problem.${problem}`, LETTER_PROBLEM_TEXT[problem])}
          </p>
        )}
      </div>
    </section>
  )
}

export default function ScopeLettersPage() {
  const { t } = useTranslation()
  const canUpload = useHasPermission(Permission.ScopeWrite)
  const canRevoke = useHasPermission(Permission.ScopeApprove)
  const { data, error, isLoading, mutate } = useLetters()
  const [uploading, setUploading] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [pendingRevoke, setPendingRevoke] = useState<AuthorizationLetter | null>(null)

  const revoke = async (l: AuthorizationLetter) => {
    setBusy(l.id)
    try {
      await revokeLetter(l.id)
      toast.success(t('letters.revoked', 'Letter revoked: entries naming it no longer authorize'))
      setPendingRevoke(null)
      await mutate()
    } catch (err) {
      toast.error(errorText(err, t('letters.revokeFailed', 'The letter could not be revoked')))
    } finally {
      setBusy(null)
    }
  }

  const download = async (l: AuthorizationLetter) => {
    try {
      await downloadLetter(l)
    } catch (err) {
      toast.error(errorText(err, t('letters.downloadFailed', 'The download failed')))
    }
  }

  return (
    <Main>
      <PageHeader
        title={t('letters.title', 'Letters of authorization')}
        description={t(
          'letters.description',
          'Signed letters that authorize testing systems your organization does not own. A letter authorizes nothing by itself: scope entries that name it need approval and stop when it expires or is revoked.'
        )}
      >
        {canUpload && (
          <Button onClick={() => setUploading((x) => !x)}>
            <Upload className="mr-2 h-4 w-4" />
            {t('letters.upload', 'Upload letter')}
          </Button>
        )}
      </PageHeader>
      <GatedSectionTabs tabs={SCOPE_SECTION_TABS} label="Scope sections" className="mt-4 mb-0" />

      <div className="space-y-6">
        {uploading && canUpload && (
          <UploadForm
            onDone={() => {
              setUploading(false)
              void mutate()
            }}
          />
        )}

        {error ? (
          <ErrorState
            title={t('letters.title', 'Letters of authorization')}
            error={error}
            onRetry={() => mutate()}
          />
        ) : !isLoading && (data ?? []).length === 0 ? (
          <EmptyState
            icon={FileSignature}
            title={t('letters.empty', 'No letters yet')}
            description={t(
              'letters.emptyHint',
              'Upload a signed letter of authorization, then add scope entries that name it.'
            )}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('letters.form.title', 'Title')}</TableHead>
                <TableHead>{t('letters.col.issuer', 'Issued by')}</TableHead>
                <TableHead>{t('letters.col.valid', 'Valid')}</TableHead>
                <TableHead>{t('letters.col.status', 'Status')}</TableHead>
                <TableHead>{t('letters.col.sha', 'SHA-256')}</TableHead>
                <TableHead className="text-right">{t('letters.col.actions', 'Actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data ?? []).map((l) => (
                <TableRow key={l.id}>
                  <TableCell className="font-medium break-words">
                    {l.title}
                    {l.reference && (
                      <span className="text-muted-foreground block text-xs">{l.reference}</span>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">{l.issuer || '-'}</TableCell>
                  <TableCell className="text-xs whitespace-nowrap">
                    {new Date(l.valid_from).toLocaleDateString()} –{' '}
                    {new Date(l.valid_until).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <LetterStatus letter={l} />
                  </TableCell>
                  <TableCell className="font-mono text-xs" title={l.file_sha256}>
                    {l.file_sha256.slice(0, 12)}…
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => download(l)}
                      aria-label={t('letters.download', 'Download')}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                    {canRevoke && !l.revoked_at && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        disabled={busy === l.id}
                        onClick={() => setPendingRevoke(l)}
                      >
                        {t('letters.revoke', 'Revoke')}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
      <ConfirmDialog
        open={pendingRevoke !== null}
        onOpenChange={(open) => !open && setPendingRevoke(null)}
        destructive
        title={t('confirm.letter.revokeTitle', 'Revoke the letter "{name}"?', {
          name: pendingRevoke?.title ?? '',
        })}
        desc={t(
          'confirm.letter.revokeDesc',
          'Scope entries that name this letter stop authorizing active scans at once. A revoked letter cannot be reinstated; upload a new letter instead.'
        )}
        confirmText={t('confirm.revoke', 'Revoke')}
        isLoading={busy !== null}
        handleConfirm={() => (pendingRevoke ? revoke(pendingRevoke) : undefined)}
      />
    </Main>
  )
}
