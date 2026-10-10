'use client'

/**
 * Import or re-import a program (RFC-065 §5, §15): details, rules and the
 * scope, entered by hand or read from a file (platform CSV export, Burp
 * Suite target scope, any CSV with chosen columns; read in the browser and
 * sent as text, never uploaded elsewhere). A new program is private by
 * default: only its members and the organization owners see it. "Preview" asks the server what the import would do and which terms
 * hash to attest to; the person then accepts the program's rules and scope
 * as previewed, and the import sends that hash. Any change to the form after
 * the preview clears it, so a person never attests to terms they have not
 * seen. The server checks the hash again and asks for step-up.
 */

import { useId, useMemo, useState } from 'react'
import { AlertTriangle, FileUp, Globe, Loader2, Lock, PenLine, Rss } from 'lucide-react'
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
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type {
  ForbiddenTechnique,
  ProgramChange,
  ProgramInput,
  ProgramPreview,
  ProgramVisibility,
  ScopeFileFormat,
} from '../api/programs-api.types'
import { previewProgram } from '../api/use-programs'
import {
  FORBIDDEN_TECHNIQUES,
  parseHeaderLines,
  parseWindowLines,
  rulesFromForm,
  SCOPE_FILE_FORMATS,
  csvHeaderColumns,
  scopeFileFromForm,
  scopeFileTooLarge,
  shortHash,
} from '../lib/program-form'
import { ProgramCatalog } from './program-catalog'
import { ProgramChoice } from './program-choice'
import { ProgramPreviewView } from './program-preview'

/**
 * How the scope is given: typed or pasted, read from a file, or followed
 * from the public program catalog (new programs only).
 */
export type ProgramScopeMode = 'manual' | 'file' | 'public'

const NO_COLUMN = '__none__'

export interface ProgramFormValues {
  name: string
  platform: string
  handle: string
  programUrl: string
  scopeText: string
  rateLimit: string
  headers: string
  userAgent: string
  forbidden: ForbiddenTechnique[]
  notes: string
  /** Testing windows, one "mon-fri 09:00-17:00 Europe/Paris" per line. */
  windows: string
  mode: ProgramScopeMode
  fileName: string
  fileContent: string
  fileFormat: ScopeFileFormat
  mapIdentifier: string
  mapType: string
  mapInScope: string
  visibility: ProgramVisibility
  termsText: string
}

export const EMPTY_PROGRAM_FORM: ProgramFormValues = {
  name: '',
  platform: '',
  handle: '',
  programUrl: '',
  scopeText: '',
  rateLimit: '',
  headers: '',
  userAgent: '',
  forbidden: [],
  notes: '',
  windows: '',
  mode: 'manual',
  fileName: '',
  fileContent: '',
  fileFormat: 'auto',
  mapIdentifier: '',
  mapType: '',
  mapInScope: '',
  visibility: 'private',
  termsText: '',
}

interface ProgramFormProps {
  initial?: ProgramFormValues
  /** Re-import of an existing program: the name is fixed. */
  existing?: boolean
  submitLabel: string
  onSubmit: (input: ProgramInput) => Promise<ProgramChange>
  onDone: (change: ProgramChange) => void
}

function errorText(err: unknown, fallback: string): string {
  if (err instanceof ApiClientError) return err.message
  return fallback
}

export function ProgramForm({
  initial,
  existing,
  submitLabel,
  onSubmit,
  onDone,
}: ProgramFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const [v, setV] = useState<ProgramFormValues>(initial ?? EMPTY_PROGRAM_FORM)
  const [preview, setPreview] = useState<ProgramPreview | null>(null)
  const [accepted, setAccepted] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const badHeaders = useMemo(() => parseHeaderLines(v.headers).invalid, [v.headers])
  const badWindows = useMemo(() => parseWindowLines(v.windows).invalid, [v.windows])
  const columns = useMemo(
    () => (v.fileFormat === 'generic_csv' ? csvHeaderColumns(v.fileContent) : []),
    [v.fileFormat, v.fileContent]
  )
  const fileMissing =
    v.mode === 'file' && (!v.fileContent || (v.fileFormat === 'generic_csv' && !v.mapIdentifier))

  const input = (accept?: string): ProgramInput => ({
    name: v.name.trim(),
    platform: v.platform.trim(),
    handle: v.handle.trim(),
    program_url: v.programUrl.trim(),
    scope_text: v.mode === 'manual' ? v.scopeText : '',
    scope_file: v.mode === 'file' ? scopeFileFromForm(v) : undefined,
    terms_text: v.termsText,
    visibility: existing ? undefined : v.visibility,
    rules: rulesFromForm(v),
    accept_terms_sha256: accept,
  })

  const readFile = async (file: File | undefined) => {
    if (!file) return
    const content = await file.text()
    if (scopeFileTooLarge(content)) {
      setError(t('programs.file.tooLarge', 'The file is larger than 256 KiB.'))
      return
    }
    setError(null)
    setV((prev) => ({
      ...prev,
      fileName: file.name.slice(0, 200),
      fileContent: content,
      mapIdentifier: '',
      mapType: '',
      mapInScope: '',
    }))
    setPreview(null)
    setAccepted(false)
  }

  // Any change invalidates the preview and the attestation.
  const set = <K extends keyof ProgramFormValues>(k: K, value: ProgramFormValues[K]) => {
    setV((prev) => ({ ...prev, [k]: value }))
    setPreview(null)
    setAccepted(false)
  }

  const toggleForbidden = (f: ForbiddenTechnique, on: boolean) =>
    set('forbidden', on ? [...v.forbidden, f] : v.forbidden.filter((x) => x !== f))

  const runPreview = async () => {
    setBusy(true)
    setError(null)
    try {
      setPreview(await previewProgram(input()))
    } catch (err) {
      setError(errorText(err, t('programs.form.requestFailed', 'The request failed.')))
    } finally {
      setBusy(false)
    }
  }

  const submit = async () => {
    if (!preview || !accepted) return
    setBusy(true)
    setError(null)
    try {
      onDone(await onSubmit(input(preview.terms_sha256)))
    } catch (err) {
      setError(errorText(err, t('programs.form.requestFailed', 'The request failed.')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      {error && (
        <div
          role="alert"
          className="bg-destructive/10 text-destructive flex items-start gap-2 rounded-md px-3 py-2 text-sm"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <section className="space-y-2">
        <h2 className="text-sm font-medium">{t('programs.source.title', 'Where is the scope?')}</h2>
        <ProgramChoice<ProgramScopeMode>
          label={t('programs.source.title', 'Where is the scope?')}
          value={v.mode}
          onChange={(m) => set('mode', m)}
          options={[
            {
              value: 'manual',
              icon: PenLine,
              title: t('programs.source.manual', 'Enter manually'),
              description: t(
                'programs.source.manualHint',
                'Paste or type the scope list from the program page.'
              ),
            },
            {
              value: 'file',
              icon: FileUp,
              title: t('programs.source.file', 'Import file'),
              description: t(
                'programs.source.fileHint',
                'The scope file the platform lets you download: CSV export, Burp Suite scope or any CSV.'
              ),
            },
            ...(existing
              ? []
              : [
                  {
                    value: 'public' as const,
                    icon: Rss,
                    title: t('programs.source.public', 'Follow a public program'),
                    description: t(
                      'programs.source.publicHint',
                      'Pick a published program; its scope stays up to date from the program feed.'
                    ),
                  },
                ]),
          ]}
        />
        <p className="text-muted-foreground text-xs">
          {t(
            'programs.source.noCredentials',
            'Private and invite-only programs work the same way: nothing is fetched from the platform and no password, cookie or token is needed.'
          )}
        </p>
      </section>

      {v.mode === 'public' && !existing ? (
        <ProgramCatalog onFollowed={onDone} onError={setError} />
      ) : (
        <>
          <section className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor={`${id}-name`}>{t('programs.form.name', 'Program name')}</Label>
              <Input
                id={`${id}-name`}
                value={v.name}
                disabled={existing}
                maxLength={200}
                onChange={(e) => set('name', e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-url`}>
                {t('programs.form.urlOptional', 'Program page URL (optional)')}
              </Label>
              <Input
                id={`${id}-url`}
                value={v.programUrl}
                placeholder="https://"
                maxLength={500}
                onChange={(e) => set('programUrl', e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-platform`}>
                {t('programs.form.platform', 'Platform (optional)')}
              </Label>
              <Input
                id={`${id}-platform`}
                value={v.platform}
                maxLength={50}
                onChange={(e) => set('platform', e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-handle`}>
                {t('programs.form.handle', 'Your handle (optional)')}
              </Label>
              <Input
                id={`${id}-handle`}
                value={v.handle}
                maxLength={100}
                onChange={(e) => set('handle', e.target.value)}
              />
            </div>
          </section>

          {!existing && (
            <section className="space-y-2">
              <h2 className="text-sm font-medium">
                {t('programs.visibility.title', 'Who can see this program')}
              </h2>
              <ProgramChoice<ProgramVisibility>
                label={t('programs.visibility.title', 'Who can see this program')}
                value={v.visibility}
                onChange={(x) => set('visibility', x)}
                options={[
                  {
                    value: 'private',
                    icon: Lock,
                    title: t('programs.visibility.private', 'Private'),
                    description: t(
                      'programs.visibility.privateHint',
                      'Only program members and organization owners; each person accepts the terms first. Every view is audited.'
                    ),
                  },
                  {
                    value: 'public',
                    icon: Globe,
                    title: t('programs.visibility.public', 'Public'),
                    description: t(
                      'programs.visibility.publicHint',
                      'Program members and everyone who sees the whole organization.'
                    ),
                  },
                ]}
              />
            </section>
          )}

          {v.mode === 'file' && (
            <section className="space-y-3">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor={`${id}-file`}>{t('programs.file.label', 'Scope file')}</Label>
                  <Input
                    id={`${id}-file`}
                    type="file"
                    accept=".csv,.tsv,.json,.txt,text/csv,application/json,text/plain"
                    onChange={(e) => void readFile(e.target.files?.[0])}
                  />
                  {v.fileName && (
                    <p className="text-muted-foreground text-xs">
                      {t('programs.file.loaded', '{name} ({size} KiB) read in your browser.', {
                        name: v.fileName,
                        size: Math.ceil(v.fileContent.length / 1024),
                      })}
                    </p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${id}-format`}>{t('programs.file.format', 'Format')}</Label>
                  <Select
                    value={v.fileFormat}
                    onValueChange={(f) => set('fileFormat', f as ScopeFileFormat)}
                  >
                    <SelectTrigger id={`${id}-format`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SCOPE_FILE_FORMATS.map((f) => (
                        <SelectItem key={f.value} value={f.value}>
                          {t(`programs.file.formats.${f.value}`, f.label)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              {v.fileFormat === 'generic_csv' && (
                <div className="grid gap-4 sm:grid-cols-3">
                  {(
                    [
                      ['mapIdentifier', t('programs.file.colIdentifier', 'Target column'), true],
                      ['mapType', t('programs.file.colType', 'Type column (optional)'), false],
                      [
                        'mapInScope',
                        t('programs.file.colInScope', 'In-scope column (optional)'),
                        false,
                      ],
                    ] as const
                  ).map(([key, label, required]) => (
                    <div key={key} className="space-y-2">
                      <Label htmlFor={`${id}-${key}`}>{label}</Label>
                      <Select
                        value={v[key] || NO_COLUMN}
                        onValueChange={(c) => set(key, c === NO_COLUMN ? '' : c)}
                        disabled={columns.length === 0}
                      >
                        <SelectTrigger id={`${id}-${key}`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {!required && (
                            <SelectItem value={NO_COLUMN}>
                              {t('programs.file.colNone', 'None')}
                            </SelectItem>
                          )}
                          {required && !v[key] && (
                            <SelectItem value={NO_COLUMN} disabled>
                              {t('programs.file.colPick', 'Choose a column')}
                            </SelectItem>
                          )}
                          {columns.map((c) => (
                            <SelectItem key={c} value={c}>
                              {c}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  ))}
                </div>
              )}
              <p className="text-muted-foreground text-xs">
                {t(
                  'programs.file.hint',
                  'A Burp Suite host expression is imported only when it names one host or one domain and its subdomains; anything wider is listed as not scannable. Nothing is created before you accept the preview.'
                )}
              </p>
            </section>
          )}

          <section className="space-y-2">
            <Label htmlFor={`${id}-terms`}>
              {t('programs.form.terms', 'Program terms and confidentiality (optional)')}
            </Label>
            <Textarea
              id={`${id}-terms`}
              value={v.termsText}
              rows={4}
              maxLength={20000}
              onChange={(e) => set('termsText', e.target.value)}
            />
          </section>

          {v.mode === 'manual' && (
            <section className="space-y-2">
              <Label htmlFor={`${id}-scope`}>{t('programs.form.scope', 'Scope')}</Label>
              <p className="text-muted-foreground text-xs">
                {t(
                  'programs.form.scopeHint',
                  'Paste the program scope: one target per line, with "In scope" and "Out of scope" headings (or a leading "-" for out of scope), or the program CSV export.'
                )}
              </p>
              <Textarea
                id={`${id}-scope`}
                value={v.scopeText}
                rows={10}
                className="font-mono text-xs"
                onChange={(e) => set('scopeText', e.target.value)}
              />
            </section>
          )}

          <section className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor={`${id}-rate`}>
                {t('programs.form.rate', 'Rate limit (requests per second)')}
              </Label>
              <Input
                id={`${id}-rate`}
                inputMode="numeric"
                value={v.rateLimit}
                onChange={(e) => set('rateLimit', e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-ua`}>{t('programs.form.ua', 'Required User-Agent')}</Label>
              <Input
                id={`${id}-ua`}
                value={v.userAgent}
                maxLength={200}
                onChange={(e) => set('userAgent', e.target.value)}
              />
            </div>
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor={`${id}-headers`}>
                {t('programs.form.headers', 'Required headers (one "Name: value" per line)')}
              </Label>
              <Textarea
                id={`${id}-headers`}
                value={v.headers}
                rows={3}
                className="font-mono text-xs"
                onChange={(e) => set('headers', e.target.value)}
              />
              {badHeaders.length > 0 && (
                <p className="text-destructive text-xs">
                  {t('programs.form.badHeaders', 'Lines {lines} are not "Name: value".', {
                    lines: badHeaders.join(', '),
                  })}
                </p>
              )}
            </div>
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor={`${id}-windows`}>
                {t('programs.form.windows', 'Testing windows (optional)')}
              </Label>
              <p className="text-muted-foreground text-xs">
                {t(
                  'programs.form.windowsHint',
                  'One window per line: days, start-end and the time zone, for example "mon-fri 09:00-17:00 Europe/Paris". Outside every window, scans of this program wait. None: any time.'
                )}
              </p>
              <Textarea
                id={`${id}-windows`}
                value={v.windows}
                rows={2}
                className="font-mono text-xs"
                onChange={(e) => set('windows', e.target.value)}
              />
              {badWindows.length > 0 && (
                <p className="text-destructive text-xs">
                  {t(
                    'programs.form.badWindows',
                    'Lines {lines} are not "days HH:MM-HH:MM time zone".',
                    {
                      lines: badWindows.join(', '),
                    }
                  )}
                </p>
              )}
            </div>
            <fieldset className="space-y-2 sm:col-span-2">
              <legend className="text-sm font-medium">
                {t('programs.form.forbidden', 'The program forbids')}
              </legend>
              <div className="grid gap-2 sm:grid-cols-3">
                {FORBIDDEN_TECHNIQUES.map((f) => (
                  <label key={f.value} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={v.forbidden.includes(f.value)}
                      onCheckedChange={(c) => toggleForbidden(f.value, c === true)}
                    />
                    {t(`programs.forbidden.${f.value}`, f.label)}
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor={`${id}-notes`}>
                {t('programs.form.notes', 'Other rules (notes)')}
              </Label>
              <Textarea
                id={`${id}-notes`}
                value={v.notes}
                rows={3}
                maxLength={4000}
                onChange={(e) => set('notes', e.target.value)}
              />
            </div>
          </section>

          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              onClick={runPreview}
              disabled={busy || badHeaders.length > 0 || badWindows.length > 0 || fileMissing}
            >
              {busy && !preview && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('programs.form.preview', 'Preview')}
            </Button>
          </div>

          {preview && (
            <section className="space-y-4 rounded-md border p-4">
              <ProgramPreviewView preview={preview} />
              <label className="flex items-start gap-2 text-sm">
                <Checkbox checked={accepted} onCheckedChange={(c) => setAccepted(c === true)} />
                <span>
                  {t(
                    'programs.form.attest',
                    'I accept this program rules and scope as shown above (terms {hash}). Its entries take effect at once, without an approver; this acceptance is recorded with my name.',
                    { hash: shortHash(preview.terms_sha256) }
                  )}
                </span>
              </label>
              <Button onClick={submit} disabled={busy || !accepted}>
                {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {submitLabel}
              </Button>
            </section>
          )}
        </>
      )}
    </div>
  )
}
