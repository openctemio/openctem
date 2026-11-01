'use client'

import { useEffect, useId, useState } from 'react'
import { FlaskConical, Loader2, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  createContentRule,
  invalidateContentRules,
  testContentRule,
  updateContentRule,
} from '../api/use-content-rules'
import {
  emptyForm,
  emptyMatcher,
  FINGERPRINT_LOCATIONS,
  fromRule,
  parseHeaders,
  type RuleForm,
  SECRET_CATEGORIES,
  SECRET_LOCATIONS,
  SEVERITIES,
  splitList,
  TECH_CATEGORIES,
  toRule,
} from '../lib/rule-form'
import type { ContentRule, ContentRuleTestResult, MatcherLocation, RuleKind } from '../types'

/** The largest sample the API tests a rule against (256 KiB). */
const MAX_SAMPLE_BYTES = 256 * 1024

interface ContentRuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The rule to edit; null creates one. */
  rule: ContentRule | null
}

interface Option {
  value: string
  label: string
}

function PickOne({
  id,
  value,
  options,
  onChange,
  disabled,
}: {
  id: string
  value: string
  options: Option[]
  onChange: (v: string) => void
  disabled?: boolean
}) {
  return (
    <Select value={value} onValueChange={onChange} disabled={disabled}>
      <SelectTrigger id={id} className="w-full">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

/**
 * New rule / edit rule: kind, id, name, what it detects, its matchers, and a
 * test against a pasted sample (secrets come back masked).
 */
export function ContentRuleDialog({ open, onOpenChange, rule }: ContentRuleDialogProps) {
  const { t } = useTranslation()
  const uid = useId()
  const [form, setForm] = useState<RuleForm>(emptyForm())
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sampleBody, setSampleBody] = useState('')
  const [sampleTitle, setSampleTitle] = useState('')
  const [sampleURL, setSampleURL] = useState('')
  const [sampleHeaders, setSampleHeaders] = useState('')
  const [sampleCookies, setSampleCookies] = useState('')
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<ContentRuleTestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setForm(rule ? fromRule(rule.kind, rule.rule) : emptyForm())
    setError(null)
    setResult(null)
    setTestError(null)
  }, [open, rule])

  const isSecret = form.kind === 'secret-rules'
  const set = (patch: Partial<RuleForm>) => setForm((f) => ({ ...f, ...patch }))
  const setMatcher = (i: number, patch: Partial<RuleForm['matchers'][number]>) =>
    setForm((f) => ({
      ...f,
      matchers: f.matchers.map((m, j) => (j === i ? { ...m, ...patch } : m)),
    }))

  const locationLabel = (l: MatcherLocation) => t(`contentRules.location.${l}`, l)
  const locations = (isSecret ? SECRET_LOCATIONS : FINGERPRINT_LOCATIONS).map((l) => ({
    value: l,
    label: locationLabel(l),
  }))
  const sampleTooLarge = new TextEncoder().encode(sampleBody).length > MAX_SAMPLE_BYTES

  async function submit() {
    setSaving(true)
    setError(null)
    try {
      const body = toRule(form)
      if (rule) await updateContentRule(rule.id, { rule: body })
      else await createContentRule({ kind: form.kind, rule: body })
      await invalidateContentRules()
      toast.success(t('contentRules.toast.saved', 'Rule saved'))
      onOpenChange(false)
    } catch (e) {
      setError(getErrorMessage(e, t('contentRules.toast.saveFailed', 'Could not save the rule')))
    } finally {
      setSaving(false)
    }
  }

  async function runTest() {
    if (sampleTooLarge) return
    setTesting(true)
    setTestError(null)
    setResult(null)
    try {
      const cookies = splitList(sampleCookies)
      const headers = parseHeaders(sampleHeaders)
      setResult(
        await testContentRule({
          kind: form.kind,
          rule: toRule(form),
          sample: {
            body: sampleBody || undefined,
            title: sampleTitle || undefined,
            url: sampleURL || undefined,
            headers: Object.keys(headers).length > 0 ? headers : undefined,
            cookies: cookies.length > 0 ? cookies : undefined,
          },
        })
      )
    } catch (e) {
      setTestError(getErrorMessage(e, t('contentRules.test.failed', 'Could not test the rule')))
    } finally {
      setTesting(false)
    }
  }

  const busy = saving || testing
  const matched = result && (result.technologies.length > 0 || result.secrets.length > 0)
  return (
    <Dialog open={open} onOpenChange={(o) => !saving && onOpenChange(o)}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>
            {rule
              ? t('contentRules.dialog.editTitle', 'Edit rule')
              : t('contentRules.dialog.newTitle', 'New rule')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'contentRules.dialog.description',
              'A rule reads parts of the web responses your scans already fetch. Patterns use RE2 syntax and run only near one of their keywords.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogForm
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <DialogBody className="space-y-5">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor={`${uid}-kind`}>{t('contentRules.field.kind', 'Kind')}</Label>
                <PickOne
                  id={`${uid}-kind`}
                  value={form.kind}
                  disabled={!!rule || busy}
                  onChange={(v) => {
                    const kind = v as RuleKind
                    set({ kind, matchers: [emptyMatcher(kind)] })
                  }}
                  options={[
                    {
                      value: 'web-fingerprints',
                      label: t('contentRules.kind.web-fingerprints', 'Technology'),
                    },
                    {
                      value: 'secret-rules',
                      label: t('contentRules.kind.secret-rules', 'Sensitive data'),
                    },
                  ]}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={`${uid}-id`}>{t('contentRules.field.id', 'Rule ID')}</Label>
                <Input
                  id={`${uid}-id`}
                  value={form.id}
                  maxLength={64}
                  placeholder="acme-portal"
                  className="font-mono"
                  onChange={(e) => set({ id: e.target.value })}
                  disabled={busy}
                />
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor={`${uid}-name`}>{t('contentRules.field.name', 'Name')}</Label>
                <Input
                  id={`${uid}-name`}
                  value={form.name}
                  maxLength={128}
                  onChange={(e) => set({ name: e.target.value })}
                  disabled={busy}
                />
              </div>
            </div>

            {isSecret ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-scat`}>
                    {t('contentRules.field.secretCategory', 'What it finds')}
                  </Label>
                  <PickOne
                    id={`${uid}-scat`}
                    value={form.secretCategory}
                    disabled={busy}
                    onChange={(v) => set({ secretCategory: v })}
                    options={SECRET_CATEGORIES.map((c) => ({
                      value: c,
                      label: t(`contentRules.secretCategory.${c}`, c),
                    }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-sev`}>
                    {t('contentRules.field.severity', 'Severity')}
                  </Label>
                  <PickOne
                    id={`${uid}-sev`}
                    value={form.secretSeverity}
                    disabled={busy}
                    onChange={(v) => set({ secretSeverity: v })}
                    options={SEVERITIES.map((s) => ({
                      value: s,
                      label: t(`contentRules.severity.${s}`, s),
                    }))}
                  />
                </div>
              </div>
            ) : (
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-tname`}>
                    {t('contentRules.field.technology', 'Technology')}
                  </Label>
                  <Input
                    id={`${uid}-tname`}
                    value={form.techName}
                    maxLength={128}
                    onChange={(e) => set({ techName: e.target.value })}
                    disabled={busy}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-tcat`}>
                    {t('contentRules.field.category', 'Category')}
                  </Label>
                  <PickOne
                    id={`${uid}-tcat`}
                    value={form.techCategory || 'other'}
                    disabled={busy}
                    onChange={(v) => set({ techCategory: v })}
                    options={TECH_CATEGORIES.map((c) => ({
                      value: c,
                      label: t(`contentRules.techCategory.${c}`, c),
                    }))}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-cpe`}>{t('contentRules.field.cpe', 'CPE')}</Label>
                  <Input
                    id={`${uid}-cpe`}
                    value={form.techCpe}
                    maxLength={255}
                    placeholder="cpe:2.3:a:vendor:product:{version}:*:*:*:*:*:*:*"
                    className="font-mono text-xs"
                    onChange={(e) => set({ techCpe: e.target.value })}
                    disabled={busy}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor={`${uid}-conf`}>
                      {t('contentRules.field.confidence', 'Confidence')}
                    </Label>
                    <Input
                      id={`${uid}-conf`}
                      inputMode="numeric"
                      value={form.confidence}
                      placeholder="70"
                      onChange={(e) => set({ confidence: e.target.value.replace(/\D/g, '') })}
                      disabled={busy}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor={`${uid}-cond`}>
                      {t('contentRules.field.condition', 'Matches when')}
                    </Label>
                    <PickOne
                      id={`${uid}-cond`}
                      value={form.condition}
                      disabled={busy}
                      onChange={(v) => set({ condition: v as 'any' | 'all' })}
                      options={[
                        { value: 'any', label: t('contentRules.condition.any', 'Any matcher') },
                        { value: 'all', label: t('contentRules.condition.all', 'All matchers') },
                      ]}
                    />
                  </div>
                </div>
              </div>
            )}

            <section className="space-y-3" aria-labelledby={`${uid}-matchers`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 id={`${uid}-matchers`} className="text-sm font-medium">
                  {t('contentRules.matchers.title', 'Matchers')}
                </h3>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={
                    busy || form.matchers.length >= 8 || (isSecret && form.matchers.length >= 1)
                  }
                  onClick={() => set({ matchers: [...form.matchers, emptyMatcher(form.kind)] })}
                >
                  <Plus className="size-4" aria-hidden />
                  {t('contentRules.matchers.add', 'Add matcher')}
                </Button>
              </div>
              {form.matchers.map((m, i) => (
                <div key={i} className="space-y-3 rounded-md border p-3" data-testid="rule-matcher">
                  <div className="grid gap-3 sm:grid-cols-[12rem_1fr_auto] sm:items-end">
                    <div className="space-y-1.5">
                      <Label htmlFor={`${uid}-loc-${i}`}>
                        {t('contentRules.matchers.location', 'Reads')}
                      </Label>
                      <PickOne
                        id={`${uid}-loc-${i}`}
                        value={m.location}
                        disabled={busy}
                        onChange={(v) => setMatcher(i, { location: v as MatcherLocation })}
                        options={locations}
                      />
                    </div>
                    {m.location === 'header' ? (
                      <div className="space-y-1.5">
                        <Label htmlFor={`${uid}-hdr-${i}`}>
                          {t('contentRules.matchers.header', 'Header name')}
                        </Label>
                        <Input
                          id={`${uid}-hdr-${i}`}
                          value={m.header}
                          maxLength={64}
                          className="font-mono"
                          onChange={(e) => setMatcher(i, { header: e.target.value })}
                          disabled={busy}
                        />
                      </div>
                    ) : (
                      <div />
                    )}
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:text-destructive"
                      disabled={busy || form.matchers.length <= 1}
                      aria-label={t('contentRules.matchers.remove', 'Remove matcher {n}', {
                        n: i + 1,
                      })}
                      onClick={() => set({ matchers: form.matchers.filter((_, j) => j !== i) })}
                    >
                      <Trash2 className="size-4" aria-hidden />
                    </Button>
                  </div>
                  {m.location === 'favicon' ? (
                    <div className="space-y-1.5">
                      <Label htmlFor={`${uid}-hash-${i}`}>
                        {t('contentRules.matchers.hashes', 'Favicon hashes')}
                      </Label>
                      <Input
                        id={`${uid}-hash-${i}`}
                        value={m.hashes}
                        placeholder="-1840324437"
                        className="font-mono"
                        onChange={(e) => setMatcher(i, { hashes: e.target.value })}
                        disabled={busy}
                      />
                    </div>
                  ) : (
                    <>
                      <div className="space-y-1.5">
                        <Label htmlFor={`${uid}-kw-${i}`}>
                          {t('contentRules.matchers.keywords', 'Keywords')}
                        </Label>
                        <Input
                          id={`${uid}-kw-${i}`}
                          value={m.keywords}
                          className="font-mono"
                          onChange={(e) => setMatcher(i, { keywords: e.target.value })}
                          disabled={busy}
                          aria-describedby={`${uid}-kw-help-${i}`}
                        />
                        <p id={`${uid}-kw-help-${i}`} className="text-xs text-muted-foreground">
                          {t(
                            'contentRules.matchers.keywordsHelp',
                            'Separated by commas, 3 to 64 characters each, any case. Required when the matcher reads the body or scripts.'
                          )}
                        </p>
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor={`${uid}-pat-${i}`}>
                          {t('contentRules.matchers.pattern', 'Pattern (RE2)')}
                        </Label>
                        <Input
                          id={`${uid}-pat-${i}`}
                          value={m.pattern}
                          maxLength={512}
                          spellCheck={false}
                          className="font-mono text-xs"
                          placeholder={
                            isSecret
                              ? '\\b(?P<secret>acme_[a-z0-9]{24})\\b'
                              : '(?i)^acme/(?P<version>[0-9.]+)'
                          }
                          onChange={(e) => setMatcher(i, { pattern: e.target.value })}
                          disabled={busy}
                          aria-describedby={`${uid}-pat-help-${i}`}
                        />
                        <p id={`${uid}-pat-help-${i}`} className="text-xs text-muted-foreground">
                          {isSecret
                            ? t(
                                'contentRules.matchers.patternHelpSecret',
                                'The group (?P<secret>…) is the value; only a masked preview, its length and where it was found are ever kept.'
                              )
                            : t(
                                'contentRules.matchers.patternHelpTech',
                                'The group (?P<version>…) is the version; {placeholder} in the CPE is replaced by it.',
                                { placeholder: '{version}' }
                              )}
                        </p>
                      </div>
                    </>
                  )}
                </div>
              ))}
            </section>

            <section
              className="space-y-3 rounded-md bg-muted/40 p-3"
              aria-labelledby={`${uid}-test`}
            >
              <h3 id={`${uid}-test`} className="text-sm font-medium">
                {t('contentRules.test.title', 'Test on a sample')}
              </h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-surl`}>{t('contentRules.test.url', 'URL')}</Label>
                  <Input
                    id={`${uid}-surl`}
                    value={sampleURL}
                    onChange={(e) => setSampleURL(e.target.value)}
                    disabled={busy}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-stitle`}>
                    {t('contentRules.test.titleField', 'Title')}
                  </Label>
                  <Input
                    id={`${uid}-stitle`}
                    value={sampleTitle}
                    onChange={(e) => setSampleTitle(e.target.value)}
                    disabled={busy}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-shdr`}>
                    {t('contentRules.test.headers', 'Headers (one "name: value" per line)')}
                  </Label>
                  <Textarea
                    id={`${uid}-shdr`}
                    value={sampleHeaders}
                    rows={2}
                    spellCheck={false}
                    className="font-mono text-xs"
                    onChange={(e) => setSampleHeaders(e.target.value)}
                    disabled={busy}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`${uid}-scookie`}>
                    {t('contentRules.test.cookies', 'Cookie names')}
                  </Label>
                  <Input
                    id={`${uid}-scookie`}
                    value={sampleCookies}
                    className="font-mono"
                    onChange={(e) => setSampleCookies(e.target.value)}
                    disabled={busy}
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={`${uid}-sbody`}>
                  {t('contentRules.test.body', 'Body (HTML, JavaScript or JSON)')}
                </Label>
                <Textarea
                  id={`${uid}-sbody`}
                  value={sampleBody}
                  rows={6}
                  spellCheck={false}
                  className="font-mono text-xs"
                  onChange={(e) => setSampleBody(e.target.value)}
                  disabled={busy}
                />
                {sampleTooLarge && (
                  <p className="text-xs text-destructive">
                    {t('contentRules.test.tooLarge', 'The sample is larger than 256 KB.')}
                  </p>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  disabled={busy || sampleTooLarge}
                  onClick={() => void runTest()}
                >
                  {testing ? (
                    <Loader2 className="size-4 animate-spin" aria-hidden />
                  ) : (
                    <FlaskConical className="size-4" aria-hidden />
                  )}
                  {t('contentRules.test.run', 'Test')}
                </Button>
                <p className="text-xs text-muted-foreground">
                  {t(
                    'contentRules.test.note',
                    'The sample is not stored. Matched secrets are shown masked.'
                  )}
                </p>
              </div>
              <div role="status" aria-live="polite" className="space-y-2 text-sm">
                {testError && <p className="text-destructive">{testError}</p>}
                {result && !matched && (
                  <p className="text-muted-foreground">
                    {t('contentRules.test.noMatch', 'No match in the sample.')}
                  </p>
                )}
                {result?.technologies.map((tm) => (
                  <div key={tm.rule_id} className="flex flex-wrap items-center gap-2">
                    <Badge variant="secondary" className="font-normal">
                      {t('contentRules.test.detected', 'Detected')}
                    </Badge>
                    <span className="font-medium">{tm.name}</span>
                    {tm.version && <span className="tabular-nums">{tm.version}</span>}
                    {tm.cpe && (
                      <code className="text-xs break-all text-muted-foreground">{tm.cpe}</code>
                    )}
                  </div>
                ))}
                {result?.secrets.map((s, i) => (
                  <div
                    key={`${s.field}-${s.line}-${s.column}-${i}`}
                    className="flex flex-wrap items-center gap-2"
                  >
                    <Badge variant="destructive" className="font-normal">
                      {t(`contentRules.severity.${s.severity}`, s.severity)}
                    </Badge>
                    <code className="text-xs">{s.preview || '…'}</code>
                    <span className="text-xs text-muted-foreground">
                      {t(
                        'contentRules.test.where',
                        '{field}, line {line}, column {column}, {length} characters',
                        {
                          field: s.field,
                          line: s.line,
                          column: s.column,
                          length: s.length,
                        }
                      )}
                    </span>
                  </div>
                ))}
                {result?.stopped && (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'contentRules.test.stopped',
                      'The test stopped at its limit; the rule may be too broad.'
                    )}
                  </p>
                )}
              </div>
            </section>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={saving}
            >
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              type="submit"
              disabled={
                busy ||
                form.id.trim() === '' ||
                form.name.trim() === '' ||
                (!isSecret && form.techName.trim() === '')
              }
            >
              {saving && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {t('contentRules.save', 'Save')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
