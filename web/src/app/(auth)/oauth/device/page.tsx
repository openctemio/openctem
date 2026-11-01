import type { Metadata } from 'next'

import { TenantProvider } from '@/context/tenant-provider'
import { DeviceCodeView } from '@/features/mcp-oauth/components/device-code-view'

export const metadata: Metadata = {
  title: 'Connect a terminal',
  robots: { index: false, follow: false },
}

/**
 * /oauth/device: the verification page of the device authorization grant
 * (api docs/rfcs/RFC-062 §6a). The page needs a signed-in session: without
 * one the proxy sends the person to sign in and back here.
 */
export default function DeviceCodePage() {
  return (
    <TenantProvider>
      <DeviceCodeView />
    </TenantProvider>
  )
}
