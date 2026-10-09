import type { Metadata } from 'next'

import { TenantProvider } from '@/context/tenant-provider'
import { ConfirmView } from '@/features/mcp-oauth/components/confirm-view'

export const metadata: Metadata = {
  title: 'Confirm a change',
  robots: { index: false, follow: false },
}

interface ConfirmPageProps {
  params: Promise<{ id: string }>
}

/**
 * /mcp/confirm/<id>: an AI application asked to change data (RFC-062 §10).
 * The page needs a signed-in session; the proxy sends the person to sign in
 * and back here.
 */
export default async function ConfirmPage({ params }: ConfirmPageProps) {
  const { id } = await params
  return (
    <TenantProvider>
      <ConfirmView id={id ?? null} />
    </TenantProvider>
  )
}
