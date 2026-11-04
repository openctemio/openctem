'use client'

import { useMemo } from 'react'
import { Bug, ClipboardCopy } from 'lucide-react'
import { toast } from 'sonner'
import { SafeExternalLink } from '@/components/safe-external-link'
import { Button } from '@/components/ui/button'
import { useBrand } from '@/context/brand-provider'
import { useTranslation } from '@/context/i18n-provider'
import { currentShell, useBuildVersions } from '@/hooks/use-build-versions'
import { classifyError } from '@/lib/client-errors'
import { copyToClipboard } from '@/lib/clipboard'
import {
  browserName,
  bugReportUrl,
  diagnosticsText,
  safeErrorCode,
  safeRequestId,
  stripRoute,
  type Diagnostics,
} from '@/lib/report-problem'

interface ReportProblemProps {
  /** The caught error: only its code, kind and request ID are used, never its message. */
  error?: unknown
  /** Button size; the error pages use the default, inline states use sm. */
  size?: 'default' | 'sm'
}

/**
 * "Report this problem" and "Copy diagnostics" for an error page or a failed
 * load. The report link opens the bug form in the person's browser with the
 * safe diagnostics filled in (src/lib/report-problem.ts), for them to review
 * before they submit. When the operator pointed the bug link at their own
 * tracker the link carries no parameters, and when they hid the links only
 * "Copy diagnostics" stays (it never leaves the browser, so an air-gapped
 * install can paste it into its own helpdesk).
 */
export function ReportProblem({ error, size = 'sm' }: ReportProblemProps) {
  const { t } = useTranslation()
  const { help } = useBrand()
  const shell = currentShell()
  const { web } = useBuildVersions(shell, true)

  const diagnostics = useMemo<Diagnostics>(() => {
    const e = error as { code?: unknown; requestId?: unknown } | null | undefined
    return {
      version: web?.version ?? 'unknown',
      channel: web?.channel ?? 'unknown',
      console: shell,
      browser: browserName(typeof navigator === 'undefined' ? '' : navigator.userAgent),
      route: stripRoute(typeof window === 'undefined' ? '/' : window.location.pathname),
      requestId: safeRequestId(e?.requestId),
      errorCode: safeErrorCode(e?.code) || classifyError(error, 'other'),
    }
  }, [error, shell, web])

  const copy = async () => {
    const ok = await copyToClipboard(diagnosticsText(diagnostics))
    if (ok) toast.success(t('help.diagnosticsCopied', 'Diagnostics copied'))
    else toast.error(t('help.diagnosticsCopyFailed', 'Could not copy the diagnostics'))
  }

  return (
    <>
      {!help.hidden && (
        <Button asChild variant="ghost" size={size}>
          <SafeExternalLink
            href={help.bugIsDefault ? bugReportUrl(diagnostics) : help.bugUrl}
            urlOptions={{ allowRelative: false }}
          >
            <Bug aria-hidden />
            {t('help.reportProblem', 'Report this problem')}
            <span className="sr-only">{t('help.opensInNewTab', '(opens in a new tab)')}</span>
          </SafeExternalLink>
        </Button>
      )}
      <Button variant="ghost" size={size} onClick={() => void copy()}>
        <ClipboardCopy aria-hidden />
        {t('help.copyDiagnostics', 'Copy diagnostics')}
      </Button>
    </>
  )
}
