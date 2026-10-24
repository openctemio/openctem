'use client'

import { ErrorState } from './error-state'

// A permission the caller lacks, in the same words and surface as a refused
// read (a 403 that names no module): "You do not have access to {title}".
const NO_ACCESS = { statusCode: 403, code: 'FORBIDDEN' }

/** Shown in place of a page's content when the user lacks the permission to read it. */
export function NoAccessState({ title }: { title: string }) {
  return <ErrorState title={title} error={NO_ACCESS} />
}
