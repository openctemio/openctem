import { EntryCard } from '@/components/entry'
import { TwoFactorSetup } from '@/features/auth/components/two-factor-setup'

interface TwoFactorSetupPageProps {
  searchParams: Promise<{ next?: string }>
}

/**
 * Where a signed-in person lands when an organization's two-factor policy
 * holds their session back (a refused token refresh). They stay signed in and
 * set it up here, then return to the page they were on.
 */
export default async function TwoFactorSetupPage({ searchParams }: TwoFactorSetupPageProps) {
  const { next } = await searchParams
  return (
    <EntryCard>
      <TwoFactorSetup next={next} />
    </EntryCard>
  )
}
