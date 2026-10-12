import type { Metadata } from 'next'

import { TenantProvider } from '@/context/tenant-provider'
import { ConsentView } from '@/features/mcp-oauth/components/consent-view'

export const metadata: Metadata = {
  title: 'Connect an application',
  robots: { index: false, follow: false },
}

interface ConsentPageProps {
  searchParams: Promise<{ request?: string | string[] }>
}

/**
 * /oauth/consent?request=<id>: an AI application (MCP client) asks to
 * connect (RFC-062). The page needs a signed-in session: without one the
 * proxy sends the person to sign in and back here.
 */
export default async function ConsentPage({ searchParams }: ConsentPageProps) {
  const { request } = await searchParams
  const requestId = typeof request === 'string' ? request : null
  return (
    <TenantProvider>
      <ConsentView requestId={requestId} />
    </TenantProvider>
  )
}
