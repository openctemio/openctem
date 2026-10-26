'use client'

import {
  DeleteAccountCard,
  PasswordCard,
  SessionsCard,
  TwoFactorCard,
  useProfile,
  useSessions,
} from '@/features/account'
import { PageStack } from '@/features/shared'

/**
 * My account → Security: password, two-factor authentication and the
 * devices signed in to the account.
 */
export default function SecurityPage() {
  const { profile } = useProfile()
  const { sessions, activeApiKeys, isLoading, mutate: mutateSessions } = useSessions()

  return (
    <PageStack>
      <PasswordCard
        isLocalAccount={profile ? profile.auth_provider === 'local' : true}
        onChanged={() => mutateSessions()}
        activeApiKeys={activeApiKeys}
      />
      <TwoFactorCard email={profile?.email} onOtherSessionsSignedOut={() => mutateSessions()} />
      <SessionsCard
        sessions={sessions}
        isLoading={isLoading}
        onChanged={() => mutateSessions()}
        activeApiKeys={activeApiKeys}
      />
      <DeleteAccountCard email={profile?.email} />
    </PageStack>
  )
}
