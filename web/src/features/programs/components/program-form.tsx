'use client'

/**
 * Import or re-import a program (RFC-065 §5): details, rules and the pasted
 * scope; "Preview" asks the server what the import would do and which terms
 * hash to attest to; the person then accepts the program's rules and scope
 * as previewed, and the import sends that hash. Any change to the form after
 * the preview clears it, so a person never attests to terms they have not
 * seen. The server checks the hash again and asks for step-up.
 */

import { useId, useMemo, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type {
  ForbiddenTechnique,
  ProgramChange,
  ProgramInput,
  ProgramPreview,
} from '../api/programs-api.types'
import { previewProgram } from '../api/use-programs'
import {
  FORBIDDEN_TECHNIQUES,
  parseHeaderLines,
  parseWindowLines,
  rulesFromForm,
  shortHash,
} from '../lib/program-form'
import { ProgramPreviewView } from './program-preview'

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
}

interface ProgramFormProps {
  initial?: ProgramFormValues
  /** Re-import of an existing program: the name is fixed. */
  existing?: boolean
  submitLabel: string
  onSubmit: (input: ProgramInput) => Promise<ProgramChange>
  onDone: (change: ProgramChange) => void
}

function errorText(err: unknown): string {
  if (err instanceof ApiClientError) return err.message
  return 'The request failed.'
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

  const input = (accept?: string): ProgramInput => ({
    name: v.name.trim(),
    platform: v.platform.trim(),
    handle: v.handle.trim(),
    program_url: v.programUrl.trim(),
    scope_text: v.scopeText,
    rules: rulesFromForm(v),
    accept_terms_sha256: accept,
  })

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
      setError(errorText(err))
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
      setError(errorText(err))
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
          <Label htmlFor={`${id}-url`}>{t('programs.form.url', 'Program policy URL')}</Label>
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
          <Label htmlFor={`${id}-notes`}>{t('programs.form.notes', 'Other rules (notes)')}</Label>
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
          disabled={busy || badHeaders.length > 0 || badWindows.length > 0}
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
    </div>
  )
}
