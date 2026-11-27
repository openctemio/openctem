import { EntryFrame } from '@/components/entry'
import { legalConfig } from '@/lib/legal'
import { legalSettings } from '@/lib/legal-settings'

type AuthLayoutProps = {
  children: React.ReactNode
}

/** Every page of this group sits in the entry frame (no app shell). */
export default async function AuthLayout({ children }: AuthLayoutProps) {
  const legal = legalConfig(await legalSettings())
  return (
    <EntryFrame termsUrl={legal.termsUrl} privacyUrl={legal.privacyUrl}>
      {children}
    </EntryFrame>
  )
}
