'use client'

/**
 * Editor for a finding's retest check (design: research/221): an HTTP
 * assertion (request + matchers, no code) or a nuclei template (pasted,
 * uploaded, or picked from the organization's template library).
 *
 *   [HTTP assertion | Nuclei template]
 *   …fields…
 *   Validate -> errors per field, tier badge + reason, generated YAML
 *   Save (only after a valid validation of exactly this input)
 *
 * The target is always the finding's own target, so there is no target field.
 * Credentials (Authorization, Cookie headers) are refused by the API; the
 * form warns before sending. The API validates and decides the tier; this
 * form only shapes the request.
 */

import { useMemo, useState, type ChangeEvent } from 'react'
import { toast } from 'sonner'
import { Loader2, Plus, Trash2, Upload } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/context/permission-provider'
import { useTranslation } from '@/context/i18n-provider'
import { Permission } from '@/lib/permissions/constants'
import { useScannerTemplates } from '@/lib/api/scanner-template-hooks'
import {
  MAX_TEMPLATE_FILE_BYTES,
  useSaveRetestCheck,
  useValidateRetestCheck,
  type HTTPAssertion,
  type HTTPAssertionMatcher,
  type HTTPAssertionMethod,
  type MatcherPart,
  type RetestCheck,
  type RetestCheckKind,
  type RetestCheckPutBody,
  type RetestCheckValidation,
  type RetestCheckValidationError,
} from '../../api/use-finding-retest-check'
import { RetestCheckTierBadge } from './retest-check-tier-badge'

const METHODS: HTTPAssertionMethod[] = ['GET', 'HEAD', 'POST', 'OPTIONS']
const CREDENTIAL_HEADERS = new Set(['authorization', 'cookie', 'proxy-authorization'])
const NO_TEMPLATE = '__none__'

type MatcherType = HTTPAssertionMatcher['type']

interface MatcherRow {
  key: number
  type: MatcherType
  part: MatcherPart
  /** Status codes comma separated, or words / patterns one per line. */
  values: string
  condition: 'and' | 'or'
  negative: boolean
}

interface HeaderRow {
  key: number
  name: string
  value: string
}

let rowSeq = 0
const nextKey = () => ++rowSeq

function matcherToRow(m: HTTPAssertionMatcher): MatcherRow {
  switch (m.type) {
    case 'status':
      return {
        key: nextKey(),
        type: 'status',
        part: 'body',
        values: m.status.join(', '),
        condition: 'or',
        negative: false,
      }
    case 'word':
      return {
        key: nextKey(),
        type: 'word',
        part: m.part,
        values: m.words.join('\n'),
        condition: m.condition ?? 'or',
        negative: !!m.negative,
      }
    case 'regex':
      return {
        key: nextKey(),
        type: 'regex',
        part: m.part,
        values: m.regex.join('\n'),
        condition: 'or',
        negative: !!m.negative,
      }
  }
}

function lines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
}

function rowToMatcher(r: MatcherRow): HTTPAssertionMatcher {
  switch (r.type) {
    case 'status':
      return {
        type: 'status',
        status: r.values
          .split(/[,\s]+/)
          .map((v) => Number.parseInt(v, 10))
          .filter((n) => Number.isFinite(n)),
      }
    case 'word':
      return {
        type: 'word',
        part: r.part,
        words: lines(r.values),
        condition: r.condition,
        ...(r.negative ? { negative: true } : {}),
      }
    case 'regex':
      return {
        type: 'regex',
        part: r.part,
        regex: lines(r.values),
        ...(r.negative ? { negative: true } : {}),
      }
  }
}

function newMatcherRow(type: MatcherType = 'status'): MatcherRow {
  return {
    key: nextKey(),
    type,
    part: 'body',
    values: type === 'status' ? '200' : '',
    condition: 'or',
    negative: false,
  }
}

/** Errors for one field: the field itself or anything under it. */
function errorsFor(errors: RetestCheckValidationError[], field: string) {
  return errors.filter(
    (e) => e.field === field || e.field.startsWith(`${field}.`) || e.field.startsWith(`${field}[`)
  )
}

function FieldErrors({ errors }: { errors: RetestCheckValidationError[] }) {
  if (errors.length === 0) return null
  return (
    <ul className="space-y-0.5 text-xs text-destructive" role="alert">
      {errors.map((e, i) => (
        <li key={`${e.field}-${e.code}-${i}`}>{e.message}</li>
      ))}
    </ul>
  )
}

export interface RetestCheckEditorDialogProps {
  findingId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The current check, to edit; null to attach a new one. */
  initial: RetestCheck | null
}

export function RetestCheckEditorDialog(props: RetestCheckEditorDialogProps) {
  // Remount on open so the form starts from the current check every time.
  if (!props.open) return null
  return <EditorDialog {...props} />
}

function EditorDialog({ findingId, open, onOpenChange, initial }: RetestCheckEditorDialogProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canReadLibrary = hasPermission(Permission.ScannerTemplatesRead)

  const initialAssertion = initial?.assertion ?? null
  const [kind, setKind] = useState<RetestCheckKind>(initial?.kind ?? 'http_assertion')
  const [name, setName] = useState(initial?.template_name ?? '')
  const [method, setMethod] = useState<HTTPAssertionMethod>(initialAssertion?.method ?? 'GET')
  const [path, setPath] = useState(initialAssertion?.path ?? '/')
  const [headers, setHeaders] = useState<HeaderRow[]>(() =>
    Object.entries(initialAssertion?.headers ?? {}).map(([n, v]) => ({
      key: nextKey(),
      name: n,
      value: v,
    }))
  )
  const [body, setBody] = useState(initialAssertion?.body ?? '')
  const [matchers, setMatchers] = useState<MatcherRow[]>(() =>
    initialAssertion?.matchers?.length
      ? initialAssertion.matchers.map(matcherToRow)
      : [newMatcherRow()]
  )
  const [matchersCondition, setMatchersCondition] = useState<'and' | 'or'>(
    initialAssertion?.matchers_condition ?? 'and'
  )
  const [content, setContent] = useState(initial?.kind === 'nuclei' ? initial.content : '')
  const [templateId, setTemplateId] = useState(
    initial?.kind === 'nuclei' && !initial.content ? initial.template_id : ''
  )
  const [fileError, setFileError] = useState('')

  const [validation, setValidation] = useState<RetestCheckValidation | null>(null)
  const [validatedFor, setValidatedFor] = useState('')

  const validate = useValidateRetestCheck(findingId)
  const save = useSaveRetestCheck(findingId)

  const putBody: RetestCheckPutBody = useMemo(() => {
    const trimmedName = name.trim()
    if (kind === 'nuclei') {
      return {
        kind,
        ...(trimmedName ? { name: trimmedName } : {}),
        ...(templateId ? { template_id: templateId } : { content }),
      }
    }
    const headerMap: Record<string, string> = {}
    for (const h of headers) if (h.name.trim()) headerMap[h.name.trim()] = h.value
    const assertion: HTTPAssertion = {
      method,
      path: path.trim(),
      ...(Object.keys(headerMap).length ? { headers: headerMap } : {}),
      ...(method === 'POST' && body ? { body } : {}),
      matchers: matchers.map(rowToMatcher),
      matchers_condition: matchersCondition,
    }
    return { kind, ...(trimmedName ? { name: trimmedName } : {}), assertion }
  }, [kind, name, templateId, content, headers, method, path, body, matchers, matchersCondition])

  const bodyKey = JSON.stringify(putBody)
  const canSave = !!validation?.valid && validatedFor === bodyKey && !save.isMutating
  const errors = validatedFor === bodyKey ? (validation?.errors ?? []) : []
  const credentialHeader = headers.some((h) => CREDENTIAL_HEADERS.has(h.name.trim().toLowerCase()))

  const runValidate = async () => {
    try {
      const result = await validate.trigger(putBody)
      setValidation(result)
      setValidatedFor(bodyKey)
    } catch (error) {
      setValidation(null)
      setValidatedFor('')
      toast.error(
        getErrorMessage(
          error,
          t('findings.retestCheck.validateFailed', 'Could not validate the check')
        )
      )
    }
  }

  const runSave = async () => {
    try {
      await save.trigger(putBody)
      toast.success(t('findings.retestCheck.saved', 'Retest check saved'))
      onOpenChange(false)
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.retestCheck.saveFailed', 'Could not save the check'))
      )
    }
  }

  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (!/\.ya?ml$/i.test(file.name)) {
      setFileError(t('findings.retestCheck.fileType', 'Choose a .yaml or .yml file.'))
      return
    }
    if (file.size > MAX_TEMPLATE_FILE_BYTES) {
      setFileError(t('findings.retestCheck.fileTooLarge', 'The file is larger than 256 KB.'))
      return
    }
    setFileError('')
    setContent(await file.text())
    setTemplateId('')
    if (!name.trim()) setName(file.name.replace(/\.ya?ml$/i, ''))
  }

  const updateMatcher = (key: number, patch: Partial<MatcherRow>) =>
    setMatchers((rows) => rows.map((r) => (r.key === key ? { ...r, ...patch } : r)))
  const updateHeader = (key: number, patch: Partial<HeaderRow>) =>
    setHeaders((rows) => rows.map((r) => (r.key === key ? { ...r, ...patch } : r)))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {initial
              ? t('findings.retestCheck.editTitle', 'Edit retest check')
              : t('findings.retestCheck.addTitle', 'Add a retest check')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'findings.retestCheck.editorDesc',
              "The check runs against this finding's own target. A match means the issue is still there. Credentials are not allowed in a check."
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="retest-check-name">{t('findings.retestCheck.name', 'Name')}</Label>
              <Input
                id="retest-check-name"
                value={name}
                maxLength={200}
                onChange={(e) => setName(e.target.value)}
                placeholder={t(
                  'findings.retestCheck.namePlaceholder',
                  'e.g. Reflected XSS on /search'
                )}
              />
              <FieldErrors errors={errorsFor(errors, 'name')} />
            </div>

            <Tabs value={kind} onValueChange={(v) => setKind(v as RetestCheckKind)}>
              <TabsList>
                <TabsTrigger value="http_assertion">
                  {t('findings.retestCheck.tabAssertion', 'HTTP assertion')}
                </TabsTrigger>
                <TabsTrigger value="nuclei">
                  {t('findings.retestCheck.tabNuclei', 'Nuclei template')}
                </TabsTrigger>
              </TabsList>

              <TabsContent value="http_assertion" className="space-y-4 pt-3">
                <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
                  <div className="space-y-1.5">
                    <Label htmlFor="retest-check-method">
                      {t('findings.retestCheck.method', 'Method')}
                    </Label>
                    <Select
                      value={method}
                      onValueChange={(v) => setMethod(v as HTTPAssertionMethod)}
                    >
                      <SelectTrigger id="retest-check-method" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {METHODS.map((m) => (
                          <SelectItem key={m} value={m}>
                            {m}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="min-w-0 space-y-1.5">
                    <Label htmlFor="retest-check-path">
                      {t('findings.retestCheck.path', 'Path')}
                    </Label>
                    <Input
                      id="retest-check-path"
                      value={path}
                      onChange={(e) => setPath(e.target.value)}
                      className="font-mono"
                      placeholder="/search?q=test"
                    />
                    <p className="text-xs text-muted-foreground">
                      {t(
                        'findings.retestCheck.pathHelp',
                        "Starts with /, relative to the finding's target."
                      )}
                    </p>
                    <FieldErrors errors={errorsFor(errors, 'assertion.path')} />
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <Label>{t('findings.retestCheck.headers', 'Headers')}</Label>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7"
                      onClick={() =>
                        setHeaders((rows) => [...rows, { key: nextKey(), name: '', value: '' }])
                      }
                    >
                      <Plus className="h-3.5 w-3.5" />
                      {t('findings.retestCheck.addHeader', 'Add header')}
                    </Button>
                  </div>
                  {headers.map((h) => (
                    <div key={h.key} className="flex gap-2">
                      <Input
                        aria-label={t('findings.retestCheck.headerName', 'Header name')}
                        value={h.name}
                        onChange={(e) => updateHeader(h.key, { name: e.target.value })}
                        className="min-w-0 flex-1 font-mono"
                        placeholder={t('findings.retestCheck.headerNamePlaceholder', 'Accept')}
                      />
                      <Input
                        aria-label={t('findings.retestCheck.headerValue', 'Header value')}
                        value={h.value}
                        onChange={(e) => updateHeader(h.key, { value: e.target.value })}
                        className="min-w-0 flex-1 font-mono"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="shrink-0"
                        aria-label={t('findings.retestCheck.removeHeader', 'Remove header')}
                        onClick={() => setHeaders((rows) => rows.filter((r) => r.key !== h.key))}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                  {credentialHeader && (
                    <p className="text-xs text-destructive">
                      {t(
                        'findings.retestCheck.noCredentials',
                        'Credentials are not allowed in a check: remove Authorization and Cookie headers.'
                      )}
                    </p>
                  )}
                  <FieldErrors errors={errorsFor(errors, 'assertion.headers')} />
                </div>

                {method === 'POST' && (
                  <div className="space-y-1.5">
                    <Label htmlFor="retest-check-body">
                      {t('findings.retestCheck.body', 'Body')}
                    </Label>
                    <Textarea
                      id="retest-check-body"
                      value={body}
                      onChange={(e) => setBody(e.target.value)}
                      className="min-h-20 font-mono text-xs"
                    />
                    <FieldErrors errors={errorsFor(errors, 'assertion.body')} />
                  </div>
                )}

                <div className="space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Label>{t('findings.retestCheck.matchers', 'Matchers')}</Label>
                    <div className="flex items-center gap-2">
                      <Select
                        value={matchersCondition}
                        onValueChange={(v) => setMatchersCondition(v as 'and' | 'or')}
                      >
                        <SelectTrigger
                          className="h-7 w-auto text-xs"
                          aria-label={t(
                            'findings.retestCheck.matchersCondition',
                            'Combine matchers'
                          )}
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="and">
                            {t('findings.retestCheck.allMatch', 'All must match')}
                          </SelectItem>
                          <SelectItem value="or">
                            {t('findings.retestCheck.anyMatch', 'Any may match')}
                          </SelectItem>
                        </SelectContent>
                      </Select>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-7"
                        onClick={() => setMatchers((rows) => [...rows, newMatcherRow('word')])}
                      >
                        <Plus className="h-3.5 w-3.5" />
                        {t('findings.retestCheck.addMatcher', 'Add matcher')}
                      </Button>
                    </div>
                  </div>
                  {matchers.map((m, i) => (
                    <MatcherEditor
                      key={m.key}
                      row={m}
                      index={i}
                      canRemove={matchers.length > 1}
                      errors={errorsFor(errors, `assertion.matchers[${i}]`)}
                      onChange={(patch) => updateMatcher(m.key, patch)}
                      onRemove={() => setMatchers((rows) => rows.filter((r) => r.key !== m.key))}
                    />
                  ))}
                  <FieldErrors
                    errors={errors.filter(
                      (e) => e.field === 'assertion.matchers' || e.field === 'assertion'
                    )}
                  />
                </div>
              </TabsContent>

              <TabsContent value="nuclei" className="space-y-3 pt-3">
                {canReadLibrary && (
                  <LibraryPicker
                    value={templateId}
                    onChange={(id) => {
                      setTemplateId(id)
                      if (id) setFileError('')
                    }}
                  />
                )}
                {!templateId && (
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Label htmlFor="retest-check-yaml">
                        {t('findings.retestCheck.yaml', 'Template YAML')}
                      </Label>
                      <Button type="button" variant="outline" size="sm" className="h-7" asChild>
                        <label className="cursor-pointer">
                          <Upload className="h-3.5 w-3.5" />
                          {t('findings.retestCheck.upload', 'Upload .yaml')}
                          <input
                            type="file"
                            accept=".yaml,.yml"
                            className="sr-only"
                            data-testid="retest-check-file"
                            onChange={(e) => void onFile(e)}
                          />
                        </label>
                      </Button>
                    </div>
                    <Textarea
                      id="retest-check-yaml"
                      value={content}
                      onChange={(e) => setContent(e.target.value)}
                      spellCheck={false}
                      className="min-h-56 font-mono text-xs"
                      placeholder={
                        'id: my-check\ninfo:\n  name: …\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/"'
                      }
                    />
                    {fileError && <p className="text-xs text-destructive">{fileError}</p>}
                  </div>
                )}
                <FieldErrors
                  errors={errors.filter(
                    (e) =>
                      e.field === 'content' ||
                      e.field.startsWith('content.') ||
                      e.field === 'template_id'
                  )}
                />
              </TabsContent>
            </Tabs>

            {validation && validatedFor === bodyKey && <ValidationResult validation={validation} />}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            variant="outline"
            onClick={() => void runValidate()}
            disabled={validate.isMutating}
          >
            {validate.isMutating && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('findings.retestCheck.validate', 'Validate')}
          </Button>
          <Button
            onClick={() => void runSave()}
            disabled={!canSave}
            title={
              canSave
                ? undefined
                : t('findings.retestCheck.saveHint', 'Validate this exact check before saving')
            }
          >
            {save.isMutating && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('findings.retestCheck.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function MatcherEditor({
  row,
  index,
  canRemove,
  errors,
  onChange,
  onRemove,
}: {
  row: MatcherRow
  index: number
  canRemove: boolean
  errors: RetestCheckValidationError[]
  onChange: (patch: Partial<MatcherRow>) => void
  onRemove: () => void
}) {
  const { t } = useTranslation()
  const n = index + 1
  return (
    <div className="space-y-2 rounded-md border p-2.5" data-testid="retest-check-matcher">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={row.type}
          onValueChange={(v) => {
            const type = v as MatcherType
            onChange({ type, values: type === 'status' ? '200' : '' })
          }}
        >
          <SelectTrigger
            className="h-8 w-auto"
            aria-label={t('findings.retestCheck.matcherType', 'Matcher {n} type', { n })}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="status">
              {t('findings.retestCheck.typeStatus', 'Status code')}
            </SelectItem>
            <SelectItem value="word">{t('findings.retestCheck.typeWord', 'Words')}</SelectItem>
            <SelectItem value="regex">{t('findings.retestCheck.typeRegex', 'Regex')}</SelectItem>
          </SelectContent>
        </Select>
        {row.type !== 'status' && (
          <Select value={row.part} onValueChange={(v) => onChange({ part: v as MatcherPart })}>
            <SelectTrigger
              className="h-8 w-auto"
              aria-label={t('findings.retestCheck.matcherPart', 'Matcher {n} part', { n })}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="body">{t('findings.retestCheck.partBody', 'in body')}</SelectItem>
              <SelectItem value="header">
                {t('findings.retestCheck.partHeader', 'in headers')}
              </SelectItem>
            </SelectContent>
          </Select>
        )}
        {row.type === 'word' && (
          <Select
            value={row.condition}
            onValueChange={(v) => onChange({ condition: v as 'and' | 'or' })}
          >
            <SelectTrigger
              className="h-8 w-auto"
              aria-label={t('findings.retestCheck.wordCondition', 'Matcher {n} words', { n })}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="or">{t('findings.retestCheck.anyWord', 'any word')}</SelectItem>
              <SelectItem value="and">{t('findings.retestCheck.allWords', 'all words')}</SelectItem>
            </SelectContent>
          </Select>
        )}
        {row.type !== 'status' && (
          <label className="flex items-center gap-1.5 text-xs">
            <Checkbox
              checked={row.negative}
              onCheckedChange={(v) => onChange({ negative: v === true })}
            />
            {t('findings.retestCheck.negative', 'must not appear')}
          </label>
        )}
        {canRemove && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="ms-auto h-8 w-8"
            aria-label={t('findings.retestCheck.removeMatcher', 'Remove matcher {n}', { n })}
            onClick={onRemove}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        )}
      </div>
      {row.type === 'status' ? (
        <Input
          aria-label={t('findings.retestCheck.statusValues', 'Matcher {n} status codes', { n })}
          value={row.values}
          onChange={(e) => onChange({ values: e.target.value })}
          className="font-mono"
          placeholder="200, 302"
        />
      ) : (
        <Textarea
          aria-label={t('findings.retestCheck.matchValues', 'Matcher {n} values, one per line', {
            n,
          })}
          value={row.values}
          onChange={(e) => onChange({ values: e.target.value })}
          className="min-h-16 font-mono text-xs"
          placeholder={t('findings.retestCheck.onePerLine', 'One per line')}
        />
      )}
      <FieldErrors errors={errors} />
    </div>
  )
}

function LibraryPicker({ value, onChange }: { value: string; onChange: (id: string) => void }) {
  const { t } = useTranslation()
  const { data, isLoading } = useScannerTemplates({
    template_type: 'nuclei',
    status: 'active',
    per_page: 100,
  })
  const items = data?.items ?? []
  return (
    <div className="space-y-1.5">
      <Label htmlFor="retest-check-library">
        {t('findings.retestCheck.library', 'Pick from the template library')}
      </Label>
      <Select
        value={value || NO_TEMPLATE}
        onValueChange={(v) => onChange(v === NO_TEMPLATE ? '' : v)}
        disabled={isLoading}
      >
        <SelectTrigger id="retest-check-library" className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={NO_TEMPLATE}>
            {t('findings.retestCheck.libraryNone', 'None: paste or upload a template')}
          </SelectItem>
          {items.map((tpl) => (
            <SelectItem key={tpl.id} value={tpl.id}>
              {tpl.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

function ValidationResult({ validation }: { validation: RetestCheckValidation }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2 rounded-md border p-3" data-testid="retest-check-validation">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className={validation.valid ? 'font-medium' : 'font-medium text-destructive'}>
          {validation.valid
            ? t('findings.retestCheck.valid', 'The check is valid')
            : t('findings.retestCheck.invalid', 'The check has errors')}
        </span>
        {validation.tier && <RetestCheckTierBadge tier={validation.tier} />}
      </div>
      {validation.tier_reason && (
        <p className="text-xs text-muted-foreground">{validation.tier_reason}</p>
      )}
      {validation.approval_required && (
        <p className="text-xs text-muted-foreground">
          {t(
            'findings.retestCheck.approvalNeeded',
            'Intrusive check: after saving, a second person with scope approval rights must approve it before it runs.'
          )}
        </p>
      )}
      {!validation.valid && validation.errors.length > 0 && (
        <ul className="space-y-0.5 text-xs text-destructive">
          {validation.errors.map((e, i) => (
            <li key={`${e.field}-${i}`}>
              {e.field ? <span className="font-mono">{e.field}</span> : null}
              {e.field ? ': ' : ''}
              {e.message}
            </li>
          ))}
        </ul>
      )}
      {validation.content && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground">
            {t('findings.retestCheck.preview', 'Template that will run')}
          </summary>
          <pre className="mt-2 max-h-64 overflow-auto rounded bg-muted p-2 font-mono whitespace-pre">
            {validation.content}
          </pre>
        </details>
      )}
    </div>
  )
}
