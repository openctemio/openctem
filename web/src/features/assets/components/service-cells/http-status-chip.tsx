import type { ReactNode } from 'react'
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
}

/**
 * "301, 200 OK": the redirect chain then the final status and its reason,
 * coloured by the final status. A missing status renders `fallback`
 * (nothing by default), never a default 200.
 */
export function HttpStatusChip({ status, chain = [], fallback = null }: HttpStatusChipProps) {
  if (status === null) return <>{fallback}</>
  const reason = httpReason(status)
  const codes = [...chain, status].join(', ')
  const title =
    chain.length > 0
      ? `Redirect chain: ${[...chain, status].join(' → ')}`
      : `HTTP ${status}${reason ? ` ${reason}` : ''}`
  return (
    <FactChip tone={httpStatusTone(status)} title={title} aria-label={title}>
      <ChipMono>{codes}</ChipMono>
      {reason && <span>{reason}</span>}
    </FactChip>
  )
}
