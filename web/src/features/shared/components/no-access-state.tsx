'use client'

import { AccessNotice } from './access-notice'

/**
 * Shown in place of a page's content when the user lacks the permission to
 * read it: the same notice as a refused read ("You do not have access to
 * {title}"), naming the permission and who holds it when the caller knows it.
 */
export function NoAccessState({ title, permission }: { title: string; permission?: string }) {
  return (
    <AccessNotice
      kind="no_access"
      title={title}
      details={permission ? { missing_permissions: [permission] } : undefined}
    />
  )
}
