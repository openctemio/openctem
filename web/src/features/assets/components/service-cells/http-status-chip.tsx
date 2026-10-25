import type { ReactNode } from 'react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { FactChip, ChipMono, type FactChipTone } from './fact-chip'

const REASONS: Record<number, string> = {
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  204: 'No Content',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  408: 'Request Timeout',
  410: 'Gone',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
}

export function httpReason(status: number): string | undefined {
  return REASONS[status]
}

/**
 * Colour by class of the FINAL status: 2xx success, 3xx info, 401/403
 * warning (it answers, behind auth), other 4xx and 5xx destructive.
 */
export function httpStatusTone(status: number): FactChipTone {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'info'
  if (status === 401 || status === 403) return 'warning'
  if (status >= 400) return 'destructive'
  return 'muted'
}

export interface HttpStatusChipProps {
  /** The final status a probe recorded; null when none was. */
  status: number | null
  /** Redirect hops before the final status (e.g. [301]). */
  chain?: number[]
  /** Rendered when no status was recorded: nothing by default. */
  fallback?: ReactNode
  /**
   * One line of a list: the final code only ("301"), coloured by its class;
   * the reason phrase and the redirect chain are in the tooltip (and read to
   * screen readers), so the chip keeps one short width.
   */
  compact?: boolean
}

/**
 * "301, 200 OK": the redirect chain then the final status and its reason,
 * coloured by the final status. A missing status renders `fallback`
 * (nothing by default), never a default 200.
 */
export function HttpStatusChip({
  status,
  chain = [],
  fallback = null,
  compact = false,
}: HttpStatusChipProps) {
  if (status === null) return <>{fallback}</>
  const reason = httpReason(status)
  const hops = [...chain, status]
  if (compact) {
    const phrase = reason ? `${status} ${reason}` : String(status)
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <FactChip tone={httpStatusTone(status)} data-status={status}>
            <ChipMono>{status}</ChipMono>
            <span className="sr-only">
              {reason}
              {chain.length > 0 && `, ${hops.join(' → ')}`}
            </span>
          </FactChip>
        </TooltipTrigger>
        <TooltipContent side="top">
          {phrase}
          {chain.length > 0 && <span className="block font-mono">{hops.join(' → ')}</span>}
        </TooltipContent>
      </Tooltip>
    )
  }
  const codes = hops.join(', ')
  // Only a redirect chain needs a tooltip: the chip already reads "200 OK",
  // and a tooltip on every status chip covered the chips beside it.
  const title = chain.length > 0 ? `Redirect chain: ${hops.join(' → ')}` : undefined
  return (
    <FactChip tone={httpStatusTone(status)} title={title} data-status={status}>
      <ChipMono>{codes}</ChipMono>
      {reason && <span>{reason}</span>}
    </FactChip>
  )
}
