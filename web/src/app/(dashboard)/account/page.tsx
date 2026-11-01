'use client'

import { useEffect, useState } from 'react'
import { KeyValueList, PageStack } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { User, Mail, Phone, Save, Loader2, AlertCircle, Check } from 'lucide-react'
import { toast } from 'sonner'
import { useProfile, useUpdateProfile } from '@/features/account'
import { getErrorMessage } from '@/lib/api/error-handler'
import { safeAvatarSrc } from '@/lib/safe-href'
import { identityProviderLabel } from '@/lib/identity-provider-label'
import { LeaveOrganization } from '@/features/organization/components/leave-organization'
import { useTranslation } from '@/context/i18n-provider'
import { useAccountSpace } from '@/context/account-space-provider'

export default function ProfilePage() {
  const { t } = useTranslation()
  // No organization open: there is nothing to leave.
  const accountOnly = useAccountSpace()
  const { profile, isLoading, isError, error, mutate } = useProfile()
  const { updateProfile, isUpdating } = useUpdateProfile()

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
  })
  const [hasChanges, setHasChanges] = useState(false)

  // Populate form when profile loads
  useEffect(() => {
    if (profile) {
      setFormData({
        name: profile.name || '',
        phone: profile.phone || '',
      })
      setHasChanges(false)
    }
  }, [profile])

  // Track changes
  const handleChange = (field: keyof typeof formData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    const hasAnyChange =
      (field === 'name' ? value : formData.name) !== (profile?.name || '') ||
      (field === 'phone' ? value : formData.phone) !== (profile?.phone || '')
    setHasChanges(hasAnyChange)
  }

  // Save profile
  const handleSave = async () => {
    try {
      const result = await updateProfile(formData)
      if (result) {
        mutate(result)
        setHasChanges(false)
        toast.success(t('account.profile.updated', 'Profile updated'))
      }
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('account.profile.updateFailed', 'Could not update the profile'))
      )
    }
  }

  // Generate initials
  const initials = profile?.name
    ? profile.name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : profile?.email?.charAt(0).toUpperCase() || 'U'

  // Loading state
  if (isLoading) {
    return (
      <PageStack>
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-48 w-full" />
      </PageStack>
    )
  }

  // Error state
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

  return (
    <PageStack>
      {/* Profile Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            {t('account.profile.title', 'Profile information')}
          </CardTitle>
          <CardDescription>
            {t('account.profile.description', 'Your name and contact details')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col lg:flex-row gap-8">
            {/* Avatar: shows the picture from the identity provider when there is
                one, otherwise initials. There is no picture upload. */}
            <div className="flex flex-col items-center">
              <Avatar className="h-24 w-24 ring-2 ring-border">
                <AvatarImage src={safeAvatarSrc(profile?.avatar_url)} alt="" />
                <AvatarFallback className="bg-primary/10 text-2xl">{initials}</AvatarFallback>
              </Avatar>
            </div>

            {/* Form Section */}
            <div className="flex-1 space-y-4">
              {/* Name */}
              <div className="space-y-2">
                <Label htmlFor="name">{t('account.profile.fullName', 'Full name')}</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => handleChange('name', e.target.value)}
                  placeholder={t('account.profile.fullNamePlaceholder', 'Enter your full name')}
                />
              </div>

              {/* Email (read-only) */}
              <div className="space-y-2">
                <Label htmlFor="email" className="flex items-center gap-2">
                  <Mail className="h-4 w-4" />
                  {t('account.profile.email', 'Email')}
                </Label>
                <div className="flex items-center gap-2">
                  <Input id="email" value={profile?.email || ''} disabled className="bg-muted" />
                  {profile?.email_verified ? (
                    <Badge variant="outline" className="border-success/40 text-success">
                      <Check className="h-3 w-3 me-1" />
                      {t('account.profile.verified', 'Verified')}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="border-warning/40 text-warning">
                      {t('account.profile.unverified', 'Unverified')}
                    </Badge>
                  )}
                </div>
                {profile?.auth_provider && profile.auth_provider !== 'local' && (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'account.profile.managedByProvider',
                      'Managed by your identity provider ({provider})',
                      {
                        provider: identityProviderLabel(profile.auth_provider),
                      }
                    )}
                  </p>
                )}
              </div>

              {/* Phone */}
              <div className="space-y-2">
                <Label htmlFor="phone" className="flex items-center gap-2">
                  <Phone className="h-4 w-4" />
                  {t('account.profile.phone', 'Phone number')}
                </Label>
                <Input
                  id="phone"
                  type="tel"
                  value={formData.phone}
                  onChange={(e) => handleChange('phone', e.target.value)}
                  placeholder={t('account.profile.phonePlaceholder', '+84 xxx xxx xxx')}
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={!hasChanges || isUpdating}>
          {isUpdating ? (
            <Loader2 className="me-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="me-2 h-4 w-4" />
          )}
          {isUpdating
            ? t('account.saving', 'Saving...')
            : t('account.profile.save', 'Save changes')}
        </Button>
      </div>

      {/* Account Info Card */}
      <Card>
        <CardHeader>
          <CardTitle>{t('account.info.title', 'Account information')}</CardTitle>
          <CardDescription>
            {t('account.info.description', 'Details about your account')}
          </CardDescription>
        </CardHeader>
        <CardContent>
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
                value: identityProviderLabel(profile?.auth_provider),
              },
              {
                key: 'created',
                label: t('account.info.created', 'Created'),
                value: profile?.created_at
                  ? new Date(profile.created_at).toLocaleDateString()
                  : '-',
              },
              {
                key: 'updated',
                label: t('account.info.updated', 'Last updated'),
                value: profile?.updated_at
                  ? new Date(profile.updated_at).toLocaleDateString()
                  : '-',
              },
            ]}
          />
        </CardContent>
      </Card>

      {/* Every member can leave; the only owner sees why they cannot. */}
      {!accountOnly && <LeaveOrganization />}
    </PageStack>
  )
}
