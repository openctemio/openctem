'use client'

/**
 * A private program whose current terms the caller has not accepted
 * (RFC-065 §15.3): the server sends only its name, platform and terms, and
 * nothing else of it is shown until the person accepts them. The acceptance
 * is bound to the terms hash, so changed terms bring this view back.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2, Lock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import type { Program } from '../api/programs-api.types'
import { attestProgram } from '../api/use-programs'
import { shortHash } from '../lib/program-form'

interface ProgramLockedProps {
  program: Program
  onAccepted: () => void | Promise<unknown>
}

export function ProgramLocked({ program: p, onAccepted }: ProgramLockedProps) {
  const { t } = useTranslation()
  const [accepted, setAccepted] = useState(false)
  const [busy, setBusy] = useState(false)

  const accept = async () => {
    setBusy(true)
    try {
      await attestProgram(p.id, p.terms_sha256)
      toast.success(t('programs.locked.done', 'Terms accepted'))
      await onAccepted()
    } catch (err) {
      toast.error(
        err instanceof ApiClientError ? err.message : t('programs.failed', 'The change failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="max-w-3xl space-y-4 rounded-md border p-4">
      <div className="flex items-start gap-3">
        <Lock className="text-muted-foreground mt-0.5 h-5 w-5 shrink-0" aria-hidden />
        <div className="space-y-1">
          <h2 className="font-medium">{t('programs.locked.title', 'Private program')}</h2>
          <p className="text-muted-foreground text-sm">
            {t(
              'programs.locked.body',
              'Its scope, rules and link are shown only to members who accepted its current terms and confidentiality. Your acceptance is recorded with your name, and every view of this program is audited.'
            )}
          </p>
        </div>
      </div>
      {p.terms_text ? (
        <UntrustedTextBlock
          text={p.terms_text}
          label={t('programs.locked.terms', 'Program terms')}
        />
      ) : (
        <p className="text-muted-foreground text-sm">
          {t(
            'programs.locked.noTerms',
            'No terms were entered for this program; follow the terms on its platform.'
          )}
        </p>
      )}
      <label className="flex items-start gap-2 text-sm">
        <Checkbox checked={accepted} onCheckedChange={(c) => setAccepted(c === true)} />
        <span>
          {t(
            'programs.locked.attest',
            'I accept these terms and keep this program and its scope confidential (terms {hash}).',
            { hash: shortHash(p.terms_sha256) }
          )}
        </span>
      </label>
      <Button onClick={accept} disabled={busy || !accepted}>
        {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
        {t('programs.locked.accept', 'Accept and open')}
      </Button>
    </section>
  )
}
