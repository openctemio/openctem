'use client'

/**
 * New scope a sync found (RFC-065 §14): nothing is added until a person
 * reviews what accepting it would do and accepts the new terms, which is
 * recorded with their name (step-up, shared client). The server checks the
 * hash again, so terms that changed since this preview are refused.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type { Program } from '../api/programs-api.types'
import { applyPendingTerms, useProgramPending } from '../api/use-programs'
import { shortHash } from '../lib/program-form'
import { ProgramPreviewView } from './program-preview'

interface ProgramPendingTermsProps {
  program: Program
  canWrite: boolean
  onChanged: () => void | Promise<unknown>
}

export function ProgramPendingTerms({ program: p, canWrite, onChanged }: ProgramPendingTermsProps) {
  const { t } = useTranslation()
  const { data: preview, error } = useProgramPending(p.id, p.pending_terms_sha256)
  const [accepted, setAccepted] = useState(false)
  const [busy, setBusy] = useState(false)

  if (!p.pending_terms_sha256) return null

  const apply = async () => {
    if (!preview) return
    setBusy(true)
    try {
      await applyPendingTerms(p.id, preview.terms_sha256)
      toast.success(t('programs.pending.applied', 'The new scope is in effect'))
      setAccepted(false)
      await onChanged()
    } catch (err) {
      toast.error(
        err instanceof ApiClientError ? err.message : t('programs.failed', 'The change failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-3 rounded-md border border-amber-500/50 p-4">
      <h3 className="text-base font-semibold">
        {t('programs.pending.title', 'New scope found by the last sync')}
      </h3>
      <p className="text-muted-foreground text-sm">
        {t(
          'programs.pending.hint',
          'Nothing is added until someone accepts the new terms. Removals were already applied.'
        )}
      </p>
      {error && (
        <p className="text-destructive text-sm">
          {t('programs.pending.loadFailed', 'The pending terms could not be loaded.')}
        </p>
      )}
      {!preview && !error && <Loader2 className="h-4 w-4 animate-spin" />}
      {preview && (
        <>
          <ProgramPreviewView preview={preview} />
          {canWrite && (
            <>
              <label className="flex items-start gap-2 text-sm">
                <Checkbox checked={accepted} onCheckedChange={(c) => setAccepted(c === true)} />
                <span>
                  {t(
                    'programs.pending.attest',
                    'I accept the program new rules and scope as shown above (terms {hash}). The new entries take effect at once; this acceptance is recorded with my name.',
                    { hash: shortHash(preview.terms_sha256) }
                  )}
                </span>
              </label>
              <Button onClick={apply} disabled={busy || !accepted}>
                {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t('programs.pending.apply', 'Accept the new scope')}
              </Button>
            </>
          )}
        </>
      )}
    </section>
  )
}
