'use client'

import {
  DeleteAccountCard,
  PasswordCard,
  SessionsCard,
  SignInMethodsCard,
  TwoFactorCard,
  useProfile,
  useSessions,
} from '@/features/account'
import { PageStack } from '@/features/shared'

/**
 * My account → Security: password, two-factor authentication, the linked
 * Google/GitHub/Microsoft sign-in methods and the devices signed in to the
 * account.
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
      <div id="sign-in-methods" className="scroll-mt-4">
        <SignInMethodsCard />
      </div>
      <div id="sessions" className="scroll-mt-4">
        <SessionsCard
          sessions={sessions}
          isLoading={isLoading}
          onChanged={() => mutateSessions()}
          activeApiKeys={activeApiKeys}
        />
      </div>
      <DeleteAccountCard email={profile?.email} />
    </PageStack>
  )
}
