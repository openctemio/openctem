'use client'

/**
 * Paste a list into scope (RFC-054 §14): names, wildcards, addresses, ranges,
 * URLs, one per line (or separated by commas or spaces). Each is detected as
 * the entry dialog detects it and added in one POST /scope/targets/bulk
 * request (one step-up for the batch). The result lists every line's outcome:
 * added, already in scope, or refused with the server's reason.
 */

import { useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
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
import { Textarea } from '@/components/ui/textarea'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { createScopeTargetsBulk, invalidateScopeCache } from '../api/use-scope-api'
import type { ApiBulkScopeTargetsResponse, BulkScopeTargetItemInput } from '../api/scope-api.types'
import { detectScopeKind } from './scope-target-type'
import { reportBulkResult } from './add-to-scope-action'

const MAX_ITEMS = 200

/** The entries a pasted list stands for, and the tokens nothing recognizes. */
export function parseScopeList(text: string): {
  items: BulkScopeTargetItemInput[]
  unrecognized: string[]
} {
  const seen = new Set<string>()
  const items: BulkScopeTargetItemInput[] = []
  const unrecognized: string[] = []
  for (const raw of text.split(/[\s,;]+/)) {
    const token = raw.trim()
    if (!token) continue
    const kind = detectScopeKind(token)
    if (!kind) {
      unrecognized.push(token)
      continue
    }
    const pattern = kind === 'domain' ? token.toLowerCase().replace(/\.$/, '') : token
    const key = `${kind}:${pattern}`
    if (seen.has(key)) continue
    seen.add(key)
    items.push({ target_type: kind, pattern })
  }
  return { items, unrecognized }
}

interface ScopeBulkAddDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ScopeBulkAddDialog({ open, onOpenChange }: ScopeBulkAddDialogProps) {
  const { t } = useTranslation()
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ApiBulkScopeTargetsResponse | null>(null)
  const { items, unrecognized } = useMemo(() => parseScopeList(text), [text])
  const tooMany = items.length > MAX_ITEMS

  const close = (o: boolean) => {
    if (busy) return
    if (!o) {
      setText('')
      setResult(null)
    }
    onOpenChange(o)
  }

  const submit = async () => {
    setBusy(true)
    try {
      const res = await createScopeTargetsBulk({ items })
      setResult(res)
      reportBulkResult(t, res)
      await invalidateScopeCache()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scope.bulk.failed', 'Could not add to scope')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scope.list.title', 'Add a list to scope')}</DialogTitle>
          <DialogDescription>
            {t(
              'scope.list.description',
              'Paste names, wildcards (*.example.com covers the domain and every name below it), addresses, ranges or URLs, one per line. Each becomes a permanent scope entry; anything already in scope is left as it is.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3 text-sm">
          {result ? (
            <ul className="space-y-1" data-testid="scope-list-results">
              {(result.results ?? []).map((r) => (
                <li key={`${r.target_type}:${r.pattern}`} className="flex flex-wrap gap-2">
                  <span className="font-mono text-xs">{r.pattern}</span>
                  <span className="text-muted-foreground">
                    {r.result === 'created'
                      ? t('scope.list.created', 'added')
                      : r.result === 'exists'
                        ? t('scope.list.exists', 'already in scope')
                        : `${t('scope.list.refused', 'refused')}: ${r.message ?? r.code ?? ''}`}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <>
              <Label htmlFor="scope-list-text">{t('scope.list.label', 'Targets')}</Label>
              <Textarea
                id="scope-list-text"
                rows={8}
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder={'*.example.com\napi.example.org\n203.0.113.0/24'}
                className="font-mono text-xs"
              />
              <p className="text-muted-foreground">
                {t('scope.list.count', '{count} to add', { count: items.length })}
                {unrecognized.length > 0 &&
                  ` · ${t('scope.list.unrecognized', '{count} not recognized: {first}', {
                    count: unrecognized.length,
                    first: unrecognized.slice(0, 3).join(', '),
                  })}`}
              </p>
              {tooMany && (
                <p className="text-destructive">
                  {t('scope.bulk.tooMany', 'Select at most {max} at once.', { max: MAX_ITEMS })}
                </p>
              )}
            </>
          )}
        </DialogBody>
        <DialogFooter>
          {result ? (
            <Button onClick={() => close(false)}>{t('scope.list.done', 'Done')}</Button>
          ) : (
            <>
              <Button variant="outline" onClick={() => close(false)} disabled={busy}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button
                onClick={() => void submit()}
                disabled={busy || items.length === 0 || tooMany}
              >
                {busy ? t('scope.bulk.adding', 'Adding…') : t('scope.bulk.confirm', 'Add to scope')}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
