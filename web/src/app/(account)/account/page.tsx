'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  KeyValueList,
  SETTINGS_SECTION_FRAME,
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsSaveBar,
  SettingsSection,
} from '@/features/shared'
import { Input } from '@/components/ui/input'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { StatusLozenge } from '@/components/ui/status-lozenge'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertCircle, Check } from 'lucide-react'
import { toast } from 'sonner'
import { useProfile, useUpdateProfile } from '@/features/account'
import { getErrorMessage } from '@/lib/api/error-handler'
import { safeAvatarSrc } from '@/lib/safe-href'
import { identityProviderLabel } from '@/lib/identity-provider-label'
import { useTranslation } from '@/context/i18n-provider'
import { formatDate } from '@/lib/app-locale'

type ProfileForm = { name: string; phone: string }

/**
 * Account > Profile: who you are (picture from the identity provider, or
 * initials; name; e-mail with its verification), the two fields you can
 * change, and the account's details. Changes save through the save bar,
 * shown only while there are unsaved changes.
 */
export default function ProfilePage() {
  const { t } = useTranslation()
  const { profile, isLoading, isError, error, mutate } = useProfile()
  const { updateProfile, isUpdating } = useUpdateProfile()

  const saved = useMemo<ProfileForm>(
    () => ({ name: profile?.name || '', phone: profile?.phone || '' }),
    [profile?.name, profile?.phone]
  )
  const [form, setForm] = useState<ProfileForm>(saved)
  const [saveError, setSaveError] = useState<string | null>(null)

  // The saved values replace the form when they load or after a save.
  useEffect(() => {
    setForm(saved)
  }, [saved])

  const changes = [
    form.name !== saved.name && t('account.profile.fullName', 'Full name'),
    form.phone !== saved.phone && t('account.profile.phone', 'Phone number'),
  ].filter((c): c is string => !!c)
  const dirty = changes.length > 0

  const handleSave = async () => {
    setSaveError(null)
    try {
      const result = await updateProfile(form)
      if (result) {
        mutate(result)
        toast.success(t('account.profile.updated', 'Profile updated'))
      }
    } catch (err) {
      setSaveError(
        getErrorMessage(err, t('account.profile.updateFailed', 'Could not update the profile'))
      )
    }
  }

  const initials = profile?.name
    ? profile.name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : profile?.email?.charAt(0).toUpperCase() || 'U'

  if (isLoading) {
    return (
      <>
        <div className="flex items-center gap-3">
          <Skeleton className="size-12 rounded-full" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-3 w-56" />
          </div>
        </div>
        <Skeleton className="h-20 w-full" />
      </>
    )
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {t('account.profile.loadFailed', 'Could not load the profile: {message}', {
            message: error?.message || t('account.unknownError', 'Unknown error'),
          })}
        </AlertDescription>
      </Alert>
    )
  }

  // A name that is the e-mail itself (accounts created without one) shows once.
  const showName = !!saved.name && saved.name !== profile?.email

  const managedBy =
    profile?.auth_provider && profile.auth_provider !== 'local'
      ? identityProviderLabel(profile.auth_provider, t)
      : null

  return (
    <>
      <section
        data-slot="settings-section"
        aria-label={t('account.area.nav.profile', 'Profile')}
        className={SETTINGS_SECTION_FRAME}
      >
        {/* Who you are: the picture comes from the identity provider when it
            sends one (there is no upload), otherwise initials. */}
        <div className="flex min-w-0 items-center gap-3 pb-4">
          <Avatar className="size-12 shrink-0">
            <AvatarImage src={safeAvatarSrc(profile?.avatar_url)} alt="" />
            <AvatarFallback className="bg-primary/10 text-body font-medium">
              {initials}
            </AvatarFallback>
          </Avatar>
          <div className="min-w-0 flex-1">
            {showName && <p className="truncate text-body font-medium">{saved.name}</p>}
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span
                className={
                  showName
                    ? 'min-w-0 text-dense text-muted-foreground'
                    : 'min-w-0 text-body font-medium'
                }
              >
                <EmailText email={profile?.email ?? ''} />
              </span>
              {profile?.email_verified ? (
                <StatusLozenge
                  tone="resolved"
                  icon={Check}
                  label={t('account.profile.verified', 'Verified')}
                />
              ) : (
                <StatusLozenge
                  tone="accepted"
                  label={t('account.profile.unverified', 'Unverified')}
                />
              )}
            </div>
            {managedBy && (
              <p className="text-cap text-muted-foreground">
                {t(
                  'account.profile.managedByProvider',
                  'Managed by your identity provider ({provider})',
                  { provider: managedBy }
                )}
              </p>
            )}
          </div>
        </div>
        <SettingsBlock>
          <SettingsFieldGrid>
            <SettingsField id="name" label={t('account.profile.fullName', 'Full name')}>
              {(control) => (
                <Input
                  {...control}
                  autoComplete="name"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder={t('account.profile.fullNamePlaceholder', 'Enter your full name')}
                />
              )}
            </SettingsField>
            <SettingsField id="phone" label={t('account.profile.phone', 'Phone number')}>
              {(control) => (
                <Input
                  {...control}
                  type="tel"
                  autoComplete="tel"
                  value={form.phone}
                  onChange={(e) => setForm((f) => ({ ...f, phone: e.target.value }))}
                  placeholder={t('account.profile.phonePlaceholder', 'For example +1 202 555 0123')}
                />
              )}
            </SettingsField>
          </SettingsFieldGrid>
        </SettingsBlock>
      </section>

      <SettingsSection
        framed
        id="account-details"
        title={t('account.info.title', 'Account details')}
      >
        <SettingsBlock>
          <KeyValueList
            items={[
              {
                key: 'id',
                label: t('account.info.userId', 'User ID'),
                value: profile?.id || '-',
                token: true,
              },
              {
                key: 'provider',
                label: t('account.info.authProvider', 'Sign-in method'),
                value: identityProviderLabel(profile?.auth_provider, t),
              },
              {
                key: 'created',
                label: t('account.info.created', 'Created'),
                value: profile?.created_at ? formatDate(new Date(profile.created_at)) : '-',
              },
              {
                key: 'updated',
                label: t('account.info.updated', 'Last updated'),
                value: profile?.updated_at ? formatDate(new Date(profile.updated_at)) : '-',
              },
            ]}
          />
        </SettingsBlock>
      </SettingsSection>

      <SettingsSaveBar
        dirty={dirty}
        saving={isUpdating}
        onSave={handleSave}
        onDiscard={() => {
          setForm(saved)
          setSaveError(null)
        }}
        changes={changes}
        error={saveError}
      />
    </>
  )
}

/** An e-mail address that wraps only after "@" and dots, never inside a word. */
function EmailText({ email }: { email: string }) {
  const parts = email.split(/(?<=[@.])/)
  return (
    <>
      {parts.map((p, i) => (
        <span key={i}>
          {p}
          {i < parts.length - 1 && <wbr />}
        </span>
      ))}
    </>
  )
}
