'use client'

import { useEffect, useMemo, useState } from 'react'
import { EyeOff, Lock, X } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { TruncatedText } from '@/features/shared/components/truncated-text'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  AI_TERM_MAX,
  AI_TERM_MIN,
  updateAIMasking,
  useAIMasking,
  type AIMaskingPolicy,
  type AIMaskingUpdate,
} from '../api/use-ai-masking'
import { AIMaskingPreviewPanel } from './ai-masking-preview'

type T = ReturnType<typeof useTranslation>['t']

const CLASS_FALLBACK: Record<string, { title: string; desc: string }> = {
  hosts: { title: 'Host names and domains', desc: 'api.example.com becomes api.DOMAIN_x' },
  ips: {
    title: 'IP addresses and networks',
    desc: 'Keeps whether an address is public or private',
  },
  emails: { title: 'E-mail addresses', desc: 'Every e-mail address in the text' },
  users: { title: 'User names', desc: 'The people on the finding and its asset' },
  url_params: { title: 'URL ids and parameters', desc: 'Keeps the path shape and query keys' },
  orgs: { title: 'Organization names', desc: 'Your organization’s name and the terms below' },
  tickets: { title: 'Ticket ids', desc: 'PROJ-123 style ids; CVE and CWE ids stay readable' },
}

function className(t: T, c: string): string {
  return t(`settings.ai.masking.class.${c}`, CLASS_FALLBACK[c]?.title ?? c)
}

export interface Draft {
  masked: Record<string, boolean>
  subdomains: boolean
  terms: string[]
}

function draftOf(p: AIMaskingPolicy): Draft {
  return {
    masked: Object.fromEntries(p.classes.map((c) => [c.class, c.masked])),
    subdomains: p.mask_subdomain_labels,
    terms: [...p.terms],
  }
}

function bodyOf(d: Draft): AIMaskingUpdate {
  return {
    off: Object.entries(d.masked)
      .filter(([, on]) => !on)
      .map(([c]) => c),
    mask_subdomain_labels: d.subdomains,
    terms: d.terms,
  }
}

/** The change masks less than what is saved: a class or the label switch turned off, or a term removed. */
export function masksLess(saved: AIMaskingPolicy, d: Draft): boolean {
  if (saved.classes.some((c) => c.masked && d.masked[c.class] === false)) return true
  if (saved.mask_subdomain_labels && !d.subdomains) return true
  const now = new Set(d.terms.map((x) => x.toLowerCase()))
  return saved.terms.some((x) => !now.has(x.toLowerCase()))
}

/**
 * Settings > AI, "Data masking": which values are replaced by placeholders
 * before internal finding data reaches an AI model, extra terms to mask, and
 * a preview of exactly what the model would get for one finding. Secrets are
 * always masked and restricted data always fully masked (shown, not
 * switchable). Saving needs a recent sign-in (the shared API client opens the
 * re-authentication dialog); a change that masks less asks first. Renders
 * nothing until the API offers the policy (404) or for a caller who may not
 * read it.
 */
export function AIMaskingSection({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const { data, mutate } = useAIMasking(true)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [term, setTerm] = useState('')
  const [saving, setSaving] = useState(false)
  const [confirm, setConfirm] = useState(false)

  useEffect(() => {
    if (data) setDraft(draftOf(data))
  }, [data])

  const dirty = useMemo(() => {
    if (!data || !draft) return false
    return JSON.stringify(bodyOf(draft)) !== JSON.stringify(bodyOf(draftOf(data)))
  }, [data, draft])

  if (!data || !draft) return null

  const trimmed = term.trim()
  const duplicate = draft.terms.some((x) => x.toLowerCase() === trimmed.toLowerCase())
  const full = draft.terms.length >= data.max_terms
  const termError =
    trimmed === ''
      ? null
      : trimmed.length < AI_TERM_MIN || trimmed.length > AI_TERM_MAX
        ? t('settings.ai.masking.termLength', 'A term has {min} to {max} characters.', {
            min: AI_TERM_MIN,
            max: AI_TERM_MAX,
          })
        : duplicate
          ? t('settings.ai.masking.termDuplicate', 'This term is already in the list.')
          : null

  const addTerm = () => {
    if (trimmed === '' || termError || full) return
    setDraft({ ...draft, terms: [...draft.terms, trimmed] })
    setTerm('')
  }

  const save = async () => {
    setSaving(true)
    try {
      const next = await updateAIMasking(bodyOf(draft))
      await mutate(next, { revalidate: false })
      toast.success(t('settings.ai.masking.saved', 'Data masking saved'))
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const onSave = () => {
    if (!dirty || saving) return
    if (masksLess(data, draft)) {
      setConfirm(true)
      return
    }
    void save()
  }

  const disabled = !canEdit || saving

  return (
    <Card id="ai-masking">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <EyeOff className="h-4 w-4" aria-hidden />
          {t('settings.ai.masking.title', 'Data masking')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ai.masking.description',
            'Before finding data reaches an AI model, these values are replaced by placeholders. The platform keeps the real values and puts them back in the answer.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="divide-y rounded-md border">
          <div className="flex items-start gap-3 p-3" data-testid="ai-masking-secrets">
            <Switch id="ai-mask-secrets" checked disabled aria-describedby="ai-mask-secrets-desc" />
            <div className="min-w-0 flex-1 space-y-0.5">
              <Label htmlFor="ai-mask-secrets" className="flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5" aria-hidden />
                {t('settings.ai.masking.secrets', 'Secrets')}
              </Label>
              <p id="ai-mask-secrets-desc" className="text-sm text-muted-foreground">
                {t(
                  'settings.ai.masking.secretsDesc',
                  'Always masked and never put back: passwords, tokens, keys, cookies and session ids.'
                )}
              </p>
            </div>
          </div>
          {data.classes.map((c) => {
            const id = `ai-mask-${c.class}`
            return (
              <div key={c.class} className="flex items-start gap-3 p-3">
                <Switch
                  id={id}
                  checked={draft.masked[c.class] !== false}
                  disabled={disabled}
                  onCheckedChange={(on) =>
                    setDraft({ ...draft, masked: { ...draft.masked, [c.class]: on } })
                  }
                  aria-describedby={`${id}-desc`}
                />
                <div className="min-w-0 flex-1 space-y-0.5">
                  <Label htmlFor={id}>{className(t, c.class)}</Label>
                  {CLASS_FALLBACK[c.class] && (
                    <p id={`${id}-desc`} className="text-sm text-muted-foreground">
                      {t(`settings.ai.masking.classDesc.${c.class}`, CLASS_FALLBACK[c.class].desc)}
                    </p>
                  )}
                </div>
              </div>
            )
          })}
          <div className="flex items-start gap-3 p-3">
            <Switch
              id="ai-mask-subdomains"
              checked={draft.subdomains}
              disabled={disabled}
              onCheckedChange={(on) => setDraft({ ...draft, subdomains: on })}
              aria-describedby="ai-mask-subdomains-desc"
            />
            <div className="min-w-0 flex-1 space-y-0.5">
              <Label htmlFor="ai-mask-subdomains">
                {t('settings.ai.masking.subdomains', 'Mask subdomain labels too')}
              </Label>
              <p id="ai-mask-subdomains-desc" className="text-sm text-muted-foreground">
                {t(
                  'settings.ai.masking.subdomainsDesc',
                  'payroll.example.com becomes one placeholder instead of payroll.DOMAIN_x.'
                )}
              </p>
            </div>
          </div>
        </div>

        <p className="text-sm text-muted-foreground">
          {t(
            'settings.ai.masking.restricted',
            'These switches apply to internal data. Restricted data (code snippets) is always sent with every class masked, whatever is set here.'
          )}
        </p>

        <div className="space-y-2">
          {canEdit ? (
            <Label htmlFor="ai-mask-term">
              {t('settings.ai.masking.terms', 'Extra terms to mask')}
            </Label>
          ) : (
            <p className="text-sm font-medium">
              {t('settings.ai.masking.terms', 'Extra terms to mask')}
            </p>
          )}
          <p className="text-sm text-muted-foreground">
            {t(
              'settings.ai.masking.termsDesc',
              'Customer names, project code names: each is replaced by an organization placeholder. Up to {max} terms.',
              { max: data.max_terms }
            )}
          </p>
          {canEdit && (
            <div className="flex gap-2">
              <Input
                id="ai-mask-term"
                value={term}
                maxLength={AI_TERM_MAX}
                disabled={saving || full}
                onChange={(e) => setTerm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    addTerm()
                  }
                }}
                aria-invalid={!!termError}
                aria-describedby="ai-mask-term-error"
              />
              <Button
                type="button"
                variant="outline"
                onClick={addTerm}
                disabled={trimmed === '' || !!termError || full || saving}
              >
                {t('settings.ai.masking.addTerm', 'Add')}
              </Button>
            </div>
          )}
          {(termError || full) && (
            <p id="ai-mask-term-error" className="text-xs text-destructive">
              {termError ??
                t('settings.ai.masking.termsFull', 'The list is full ({max} terms).', {
                  max: data.max_terms,
                })}
            </p>
          )}
          {draft.terms.length > 0 ? (
            <ul
              className="flex flex-wrap gap-1.5"
              aria-label={t('settings.ai.masking.termList', 'Masked terms')}
            >
              {draft.terms.map((x) => (
                <li
                  key={x}
                  className="inline-flex max-w-full items-center gap-1 rounded-md border bg-muted/40 py-0.5 ps-2 pe-1 text-sm"
                >
                  <TruncatedText value={x} className="max-w-[220px]" />
                  {canEdit && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0"
                      disabled={saving}
                      aria-label={t('settings.ai.masking.removeTerm', 'Remove {term}', { term: x })}
                      onClick={() =>
                        setDraft({ ...draft, terms: draft.terms.filter((y) => y !== x) })
                      }
                    >
                      <X className="h-3.5 w-3.5" aria-hidden />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('settings.ai.masking.noTerms', 'No extra terms.')}
            </p>
          )}
        </div>

        <AIMaskingPreviewPanel />

        <div className="rounded-md border bg-muted/40 p-3 text-sm">
          <p className="font-medium">
            {t('settings.ai.masking.residualTitle', 'What masking does not hide')}
          </p>
          <ul className="mt-1 list-disc space-y-1 ps-5 text-muted-foreground">
            <li>
              {t(
                'settings.ai.masking.residualContext',
                'The surrounding text (product names, versions, paths, error messages) can still point to your organization for someone who knows it. The data class ceiling and your consent stay the main controls.'
              )}
            </li>
            <li>
              {t(
                'settings.ai.masking.residualPatterns',
                'Values in unusual formats can be missed in free text. Names the platform knows for the finding are always masked.'
              )}
            </li>
            <li>
              {t(
                'settings.ai.masking.residualCounts',
                'Lengths and counts stay visible, such as the number of hosts or a secret’s length.'
              )}
            </li>
          </ul>
        </div>

        {canEdit && (
          <SettingsSaveBar
            dirty={dirty}
            saving={saving}
            onSave={onSave}
            onDiscard={() => {
              setDraft(draftOf(data))
              setTerm('')
            }}
          />
        )}

        <ConfirmDialog
          open={confirm}
          onOpenChange={setConfirm}
          title={t('settings.ai.masking.confirmTitle', 'Mask less?')}
          desc={t(
            'settings.ai.masking.confirmDesc',
            'More of your findings’ real values will reach the AI provider. You may be asked to sign in again. The change is audited.'
          )}
          confirmText={t('settings.ai.masking.confirm', 'Save')}
          handleConfirm={async () => {
            await save()
            setConfirm(false)
          }}
        />
      </CardContent>
    </Card>
  )
}
