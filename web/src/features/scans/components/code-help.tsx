'use client'

import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { safeInternalHref } from '@/lib/safe-href'

import { failureHelp, type CodeHelp } from '../lib/placement-help'

/**
 * One code with what it means and where to fix it: the code (monospace, as
 * the API sent it), its class, the explanation, the fix and a link to the
 * page that applies it. Used for a step's error code and for each reason a
 * queued task waits.
 */
export function CodeHelpLine({ help, count }: { help: CodeHelp; count?: number }) {
  const { t } = useTranslation()
  const href = help.href ? safeInternalHref(help.href) : undefined
  return (
    <div className="space-y-0.5 text-xs" data-code={help.code}>
      <div className="flex flex-wrap items-center gap-1.5">
        <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">{help.code}</code>
        {help.classLabel && (
          <Badge variant="outline" className="px-1 py-0 text-[10px] font-normal">
            {help.classLabel}
          </Badge>
        )}
        {count !== undefined && (
          <span className="tabular-nums text-muted-foreground">
            {t('scans.placement.sensorCount', undefined, { count })}
          </span>
        )}
      </div>
      <p className="text-foreground">{help.text}</p>
      {help.fix && <p className="text-muted-foreground">{help.fix}</p>}
      {href && help.hrefLabel && (
        <Link href={href} className="font-medium text-primary underline-offset-4 hover:underline">
          {help.hrefLabel}
        </Link>
      )}
    </div>
  )
}

/** A failed step's error code, explained, with its fix. */
export function StepFailureHelp({ code, errorClass }: { code?: string; errorClass?: string }) {
  const { t } = useTranslation()
  if (!code) return null
  return <CodeHelpLine help={failureHelp(code, errorClass, t)} />
}
