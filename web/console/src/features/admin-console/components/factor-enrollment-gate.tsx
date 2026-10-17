'use client'

import { LogOut, ShieldAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { AdminStepUpPrompt } from './admin-step-up-prompt'
import { SecurityKeysPanel } from './security-keys-panel'
import type { AdminIdentity } from '../types'

/**
 * Shown instead of the console while "require security keys" holds this
 * administrator on enrollment: the API refuses every other console call (403
 * FACTOR_ENROLLMENT_REQUIRED) until they hold enough keys and unused recovery
 * codes. Registering takes a step-up, so the step-up dialog is mounted here
 * too. `onChanged` re-reads the session, which lifts the gate once compliant.
 */
export function FactorEnrollmentGate({
  admin,
  onChanged,
  onSignOut,
}: {
  admin: AdminIdentity
  onChanged: () => void
  onSignOut: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="min-h-svh px-4 py-8">
      <div className="mx-auto w-full max-w-3xl space-y-4">
        <Alert variant="destructive">
          <ShieldAlert className="size-4" />
          <AlertTitle>
            {t('admin.enroll.title', 'Register your security keys to continue')}
          </AlertTitle>
          <AlertDescription>
            {t(
              'admin.enroll.description',
              'This console now requires security keys. {email} needs at least two keys and recovery codes before the rest of the console opens.',
              { email: admin.email }
            )}
          </AlertDescription>
        </Alert>
        <SecurityKeysPanel enrollment onChanged={onChanged} />
        <div className="flex justify-end">
          <Button variant="ghost" onClick={onSignOut}>
            <LogOut className="me-1.5 size-4" />
            {t('admin.enroll.signOut', 'Sign out')}
          </Button>
        </div>
      </div>
      <AdminStepUpPrompt />
    </div>
  )
}
