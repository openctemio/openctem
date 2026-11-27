import { serverText, type Translate } from '@/lib/server-text'
import type { ValidationIssue } from '../types/ticket-mapping.types'

/**
 * A validation issue or preview note in the reader's language: the server's
 * message code (or code when there is none) and values (`serverText.ticketmap.<code>`), or the server's
 * English text when the catalog has no entry for the code.
 */
export function issueText(t: Translate, locale: string, issue: ValidationIssue): string {
  return serverText(
    t,
    locale,
    { code: `ticketmap.${issue.message_code || issue.code}`, params: issue.params },
    issue.message
  )
}
