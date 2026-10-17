'use client'

/** The fix of an action: the upgrade command to copy, or the rotation checklist. */

import { Copy } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import type { FixSteps } from '../lib/hub'

export function FixStepsBlock({ steps }: { steps: FixSteps }) {
  const { t } = useTranslation()
  const copy = async (code: string) => {
    try {
      await navigator.clipboard.writeText(code)
      toast.success(t('remediationHub.fix.copied'))
    } catch {
      toast.error(t('remediationHub.fix.copyFailed'))
    }
  }
  if (steps.kind === 'upgrade' && steps.pkg) {
    return (
      <div className="space-y-2" data-testid="fix-steps">
        <p className="text-sm">
          {t('remediationHub.fix.upgrade', undefined, {
            pkg: steps.pkg,
            version: steps.target ?? '',
          })}
        </p>
        {steps.commands.map((c) => (
          <div key={c.label} className="bg-background flex items-start gap-2 rounded-md border p-2">
            <pre className="min-w-0 flex-1 overflow-x-auto font-mono text-xs whitespace-pre">
              {c.code}
            </pre>
            <Button
              size="icon"
              variant="ghost"
              className="size-7 shrink-0"
              onClick={() => copy(c.code)}
              aria-label={t('remediationHub.fix.copy', undefined, { label: c.label })}
            >
              <Copy className="size-3.5" aria-hidden />
            </Button>
          </div>
        ))}
      </div>
    )
  }
  if (steps.kind === 'rotate') {
    return (
      <ol className="list-decimal space-y-1 ps-5 text-sm" data-testid="fix-steps">
        <li>{t('remediationHub.fix.rotate1', undefined, { prefix: steps.secretPrefix ?? '' })}</li>
        <li>{t('remediationHub.fix.rotate2')}</li>
        <li>{t('remediationHub.fix.rotate3')}</li>
      </ol>
    )
  }
  return <p className="text-muted-foreground text-sm">{t('remediationHub.fix.followFindings')}</p>
}
