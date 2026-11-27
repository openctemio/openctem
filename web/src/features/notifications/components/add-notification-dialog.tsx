'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useBrand } from '@/context/brand-provider'
import { useState, useEffect, useRef, useMemo } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { enabledEventTypesSchema, enabledSeveritiesSchema } from '../lib/notification-filters'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogBody,
  DialogFooter,
  DialogForm,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { toast } from 'sonner'
import {
  Loader2,
  Bell,
  MessageSquare,
  Send,
  Webhook,
  ChevronDown,
  Settings2,
  Mail,
} from 'lucide-react'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { useCreateNotificationIntegrationApi } from '@/features/integrations'
import {
  ALL_NOTIFICATION_SEVERITIES,
  DEFAULT_ENABLED_SEVERITIES,
  type NotificationSeverity,
} from '@/features/integrations/types/integration.types'
import { useTenantEventTypes } from '@/features/integrations/api/use-event-types'
import { EventTypeSelector } from './event-type-selector'
import { cn } from '@/lib/utils'
import { normalizePresetWebhookUrl } from '../lib/chat-presets'
import { DEFAULT_DETAIL_LEVEL, DETAIL_LEVELS } from '../lib/message-template'
import { ChannelMessageSettings } from './channel-message-settings'
import { ChannelGroupingSettings, DEFAULT_GROUPING } from './channel-grouping-settings'
import { SEVERITY_TEXT_COLORS, type SeverityLevel } from '@/lib/severity-colors'
import { getErrorMessage } from '@/lib/api/error-handler'

// Template presets for different use cases

const formSchema = z
  .object({
    name: z.string().min(1, 'Name is required').max(100),
    description: z.string().max(500).optional(),
    provider: z.enum(['slack', 'teams', 'telegram', 'webhook', 'email']),
    credentials: z.string().optional(), // For non-email providers
    channel_id: z.string().optional(),
    channel_name: z.string().optional(),
    // Severity filters (dynamic JSONB array)
    enabled_severities: enabledSeveritiesSchema,
    // Event type filters (dynamic JSONB array)
    enabled_event_types: enabledEventTypesSchema,
    // Advanced settings
    message_template: z.string().max(2000).optional(),
    detail_level: z.enum(DETAIL_LEVELS),
    group_similar: z.boolean(),
    group_window_minutes: z.number().int().min(1).max(60),
    urgent_at_once: z.boolean(),
    // Email-specific fields
    smtp_host: z.string().optional(),
    smtp_port: z.number().optional(),
    smtp_username: z.string().optional(),
    smtp_password: z.string().optional(),
    from_email: z.string().email().optional().or(z.literal('')),
    from_name: z.string().optional(),
    to_emails: z.string().optional(), // Comma-separated list
    use_tls: z.boolean().optional(),
    use_starttls: z.boolean().optional(),
    org_mail: z.boolean().optional(),
  })
  .superRefine((data, ctx) => {
    // The backend requires `credentials` for the chat/webhook providers and SMTP
    // host/from for email. These are optional at the type level (only one
    // provider's fields apply), so require the active provider's fields here —
    // otherwise an empty Slack webhook URL or missing SMTP host only failed at
    // the server with a generic 400.
    if (data.provider === 'email') {
      if (!data.smtp_host?.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['smtp_host'],
          message: 'SMTP host is required',
        })
      }
      if (!data.from_email?.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['from_email'],
          message: 'From email is required',
        })
      }
    } else if (!data.credentials?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['credentials'],
        message: 'A webhook URL / token is required for this provider',
      })
    }
  })

type FormValues = z.infer<typeof formSchema>

interface AddNotificationDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => Promise<void>
}

type Translate = ReturnType<typeof useTranslation>['t']

const buildProviders = (t: Translate) => [
  {
    id: 'slack' as const,
    provider: 'slack' as const,
    name: 'Slack',
    icon: MessageSquare,
    color: 'text-[#4A154B]',
    bgColor: 'bg-[#4A154B]/10',
    description: t('notifications.providers.slack', 'Send notifications via Slack webhook'),
    credentialLabel: 'Webhook URL',
    credentialPlaceholder: 'https://hooks.slack.com/services/...',
  },
  {
    id: 'teams' as const,
    provider: 'teams' as const,
    name: 'Microsoft Teams',
    icon: MessageSquare,
    color: 'text-[#6264A7]',
    bgColor: 'bg-[#6264A7]/10',
    description: t('notifications.providers.teams', 'Send notifications via Teams webhook'),
    credentialLabel: 'Webhook URL',
    credentialPlaceholder: 'https://outlook.office.com/webhook/...',
  },
  {
    id: 'mattermost' as const,
    provider: 'slack' as const, // Slack-format incoming webhook
    name: 'Mattermost',
    icon: MessageSquare,
    color: 'text-[#1E325C]',
    bgColor: 'bg-[#1E325C]/10',
    description: t(
      'notificationPresets.mattermost.description',
      'Send notifications to a Mattermost channel through an incoming webhook'
    ),
    credentialLabel: 'Webhook URL',
    credentialPlaceholder: 'https://chat.example.com/hooks/...',
  },
  {
    id: 'discord' as const,
    provider: 'slack' as const, // Slack-compatible endpoint (/slack) of the webhook
    name: 'Discord',
    icon: MessageSquare,
    color: 'text-[#5865F2]',
    bgColor: 'bg-[#5865F2]/10',
    description: t(
      'notificationPresets.discord.description',
      'Send notifications to a Discord channel through its webhook'
    ),
    credentialLabel: 'Webhook URL',
    credentialPlaceholder: 'https://discord.com/api/webhooks/...',
  },
  {
    id: 'telegram' as const,
    provider: 'telegram' as const,
    name: 'Telegram',
    icon: Send,
    color: 'text-[#0088cc]',
    bgColor: 'bg-[#0088cc]/10',
    description: t('notifications.providers.telegram', 'Send notifications to Telegram chat'),
    credentialLabel: 'Bot Token',
    credentialPlaceholder: '123456789:ABCdefGHIjklMNOpqrsTUVwxyz',
  },
  {
    id: 'webhook' as const,
    provider: 'webhook' as const,
    name: 'Custom Webhook',
    icon: Webhook,
    color: 'text-muted-foreground',
    bgColor: 'bg-muted',
    description: t('notifications.providers.webhook', 'Send notifications to any HTTP endpoint'),
    credentialLabel: 'Webhook URL',
    credentialPlaceholder: 'https://example.com/webhook',
  },
  {
    id: 'email' as const,
    provider: 'email' as const,
    name: 'Email (SMTP)',
    icon: Mail,
    color: 'text-muted-foreground',
    bgColor: 'bg-muted',
    description: t('notifications.providers.email', 'Send notifications via email'),
    credentialLabel: 'SMTP Configuration',
    credentialPlaceholder: '',
  },
]

type Provider = ReturnType<typeof buildProviders>[number]

export function AddNotificationDialog({
  open,
  onOpenChange,
  onSuccess,
}: AddNotificationDialogProps) {
  const { t } = useTranslation()
  const brand = useBrand()
  const providers = useMemo(() => buildProviders(t), [t])
  const [step, setStep] = useState<'provider' | 'config'>('provider')
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null)
  const [advancedOpen, setAdvancedOpen] = useState(false)

  // The event-type catalog comes from the API, module-filtered for this tenant.
  // Only fetched once the dialog is open.
  const {
    eventTypes: availableEventTypes,
    categories: eventCategories,
    defaultEnabled: defaultEventTypes,
    isLoading: eventTypesLoading,
    error: eventTypesError,
  } = useTenantEventTypes(open)

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: '',
      description: '',
      provider: 'slack',
      credentials: '',
      channel_id: '',
      channel_name: '',
      // Severity defaults
      enabled_severities: [...DEFAULT_ENABLED_SEVERITIES],
      // Event type defaults - will be updated when modules load
      enabled_event_types: [],
      // Advanced settings defaults
      message_template: '',
      detail_level: DEFAULT_DETAIL_LEVEL,
      group_similar: DEFAULT_GROUPING.group_similar,
      group_window_minutes: DEFAULT_GROUPING.group_window_minutes,
      urgent_at_once: DEFAULT_GROUPING.urgent_at_once,
      // Email defaults
      smtp_host: '',
      smtp_port: 587,
      smtp_username: '',
      smtp_password: '',
      from_email: '',
      from_name: brand.name,
      to_emails: '',
      use_tls: false,
      use_starttls: true,
      org_mail: false,
    },
  })

  // Seed the selection from the server's defaults once they arrive.
  //
  // Guarded by a ref, and an effect rather than a useMemo: this was a useMemo
  // performing a setValue during render, which re-applied the defaults on every
  // identity change of the defaults array and so silently discarded whatever
  // the operator had ticked in the meantime.
  const defaultsSeeded = useRef(false)
  useEffect(() => {
    if (!open) {
      defaultsSeeded.current = false
      return
    }
    if (defaultsSeeded.current || defaultEventTypes.length === 0) return
    defaultsSeeded.current = true
    setValue('enabled_event_types', defaultEventTypes)
  }, [open, defaultEventTypes, setValue])

  const { trigger: createIntegration, isMutating } = useCreateNotificationIntegrationApi()

  const handleProviderSelect = (provider: Provider) => {
    setSelectedProvider(provider)
    setValue('provider', provider.provider)
    setStep('config')
  }

  const handleBack = () => {
    setStep('provider')
    setSelectedProvider(null)
  }

  const handleClose = () => {
    setStep('provider')
    setSelectedProvider(null)
    setAdvancedOpen(false)
    reset()
    onOpenChange(false)
  }

  const onSubmit = async (data: FormValues) => {
    try {
      // Build credentials based on provider
      let credentials = normalizePresetWebhookUrl(
        selectedProvider?.id ?? '',
        data.credentials || ''
      )
      if (data.provider === 'email') {
        // For email, build JSON credentials
        const toEmailsList = (data.to_emails || '')
          .split(',')
          .map((e) => e.trim())
          .filter((e) => e.length > 0)

        if (toEmailsList.length === 0) {
          toast.error(
            t('notifications.dialog.recipientRequired', 'At least one recipient email is required')
          )
          return
        }

        credentials = JSON.stringify({
          smtp_host: data.smtp_host,
          smtp_port: data.smtp_port,
          username: data.smtp_username,
          password: data.smtp_password,
          from_email: data.from_email,
          from_name: data.from_name,
          to_emails: toEmailsList,
          use_tls: data.use_tls,
          use_starttls: data.use_starttls,
          org_mail: data.org_mail,
        })
      }

      await createIntegration({
        name: data.name,
        description: data.description,
        provider: data.provider,
        auth_type: 'token',
        credentials,
        channel_id: data.channel_id,
        channel_name: data.channel_name,
        // Severity filters (dynamic JSONB array)
        enabled_severities: data.enabled_severities,
        // Event type filters (dynamic JSONB array - database-driven IDs)
        enabled_event_types: data.enabled_event_types,
        // Advanced settings
        message_template: data.message_template || undefined,
        detail_level: data.detail_level,
        group_similar: data.group_similar,
        group_window_minutes: data.group_window_minutes,
        urgent_at_once: data.urgent_at_once,
      })

      toast.success(
        t('notifications.dialog.created', 'Notification channel "{name}" created', {
          name: data.name,
        })
      )
      handleClose()
      await onSuccess?.()
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to create notification channel'))
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            {step === 'provider'
              ? t('notifications.dialog.addTitle', 'Add notification channel')
              : t('notifications.dialog.configureTitle', 'Configure {provider}', {
                  provider: selectedProvider?.name ?? '',
                })}
          </DialogTitle>
          <DialogDescription>
            {step === 'provider'
              ? t(
                  'notifications.dialog.addDescription',
                  'Choose a notification provider to receive security alerts'
                )
              : t('notifications.dialog.setupDescription', 'Set up your {provider} integration', {
                  provider: selectedProvider?.name ?? '',
                })}
          </DialogDescription>
        </DialogHeader>

        {step === 'provider' ? (
          <DialogBody>
            <div className="grid grid-cols-2 gap-3 py-2">
              {providers.map((provider) => {
                const Icon = provider.icon
                return (
                  <button
                    key={provider.id}
                    type="button"
                    className={cn(
                      'flex flex-col items-center gap-2 p-4 rounded-lg border-2 transition-all',
                      'hover:border-primary hover:bg-primary/5',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2'
                    )}
                    onClick={() => handleProviderSelect(provider)}
                  >
                    <div
                      className={cn(
                        'flex h-12 w-12 items-center justify-center rounded-lg',
                        provider.bgColor
                      )}
                    >
                      <Icon className={cn('h-6 w-6', provider.color)} />
                    </div>
                    <span className="font-medium text-sm">{provider.name}</span>
                    <span className="text-xs text-muted-foreground text-center">
                      {provider.description}
                    </span>
                  </button>
                )
              })}
            </div>
          </DialogBody>
        ) : (
          <DialogForm onSubmit={handleSubmit(onSubmit)}>
            <DialogBody className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">{t('notifications.dialog.name', 'Name')}</Label>
                <Input
                  id="name"
                  placeholder={t('notifications.dialog.namePlaceholder', 'e.g., Security Alerts')}
                  {...register('name')}
                />
                {errors.name && <p className="text-sm text-destructive">{errors.name.message}</p>}
                <p className="text-xs text-muted-foreground">
                  {t(
                    'notifications.dialog.nameHelp',
                    'A friendly name for this notification channel'
                  )}
                </p>
              </div>

              {/* Non-email providers: single credential field */}
              {selectedProvider?.id !== 'email' && (
                <div className="space-y-2">
                  <Label htmlFor="credentials">{selectedProvider?.credentialLabel}</Label>
                  <Input
                    id="credentials"
                    type="password"
                    placeholder={selectedProvider?.credentialPlaceholder}
                    {...register('credentials')}
                  />
                  {errors.credentials && (
                    <p className="text-sm text-destructive">{errors.credentials.message}</p>
                  )}
                </div>
              )}

              {/* Email provider: SMTP configuration fields */}
              {selectedProvider?.id === 'email' && (
                <div className="space-y-4 rounded-lg border p-4 bg-muted/30">
                  <p className="text-sm font-medium">
                    {t('notifications.dialog.smtpConfig', 'SMTP configuration')}
                  </p>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <Label htmlFor="smtp_host">
                        {t('notifications.dialog.smtpHost', 'SMTP host')}{' '}
                        <span className="text-destructive">*</span>
                      </Label>
                      <Input
                        id="smtp_host"
                        placeholder="smtp.gmail.com"
                        {...register('smtp_host')}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="smtp_port">
                        {t('notifications.dialog.port', 'Port')}{' '}
                        <span className="text-destructive">*</span>
                      </Label>
                      <Input
                        id="smtp_port"
                        type="number"
                        placeholder="587"
                        {...register('smtp_port', { valueAsNumber: true })}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <Label htmlFor="smtp_username">
                        {t('notifications.dialog.username', 'Username')}
                      </Label>
                      <Input
                        id="smtp_username"
                        placeholder="your@email.com"
                        {...register('smtp_username')}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="smtp_password">
                        {t('notifications.dialog.password', 'Password')}
                      </Label>
                      <Input
                        id="smtp_password"
                        type="password"
                        placeholder={t('notifications.dialog.passwordPlaceholder', 'App password')}
                        {...register('smtp_password')}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <Label htmlFor="from_email">
                        {t('notifications.dialog.fromEmail', 'From email')}{' '}
                        <span className="text-destructive">*</span>
                      </Label>
                      <Input
                        id="from_email"
                        type="email"
                        placeholder="alerts@company.com"
                        {...register('from_email')}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="from_name">
                        {t('notifications.dialog.fromName', 'From name')}
                      </Label>
                      <Input id="from_name" placeholder={brand.name} {...register('from_name')} />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="to_emails">
                      {t('notifications.dialog.recipients', 'Recipients')}{' '}
                      <span className="text-destructive">*</span>
                    </Label>
                    <Input
                      id="to_emails"
                      placeholder="security@company.com, admin@company.com"
                      {...register('to_emails')}
                    />
                    <p className="text-xs text-muted-foreground">
                      {t(
                        'notifications.dialog.recipientsHelp',
                        'Comma-separated list of email addresses'
                      )}
                    </p>
                  </div>

                  <div className="flex items-center gap-6">
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="use_starttls"
                        checked={watch('use_starttls')}
                        onCheckedChange={(checked) => setValue('use_starttls', !!checked)}
                      />
                      <label htmlFor="use_starttls" className="text-sm cursor-pointer">
                        {t('notifications.dialog.starttls', 'STARTTLS (port 587)')}
                      </label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="use_tls"
                        checked={watch('use_tls')}
                        onCheckedChange={(checked) => setValue('use_tls', !!checked)}
                      />
                      <label htmlFor="use_tls" className="text-sm cursor-pointer">
                        {t('notifications.dialog.directTls', 'Direct TLS (port 465)')}
                      </label>
                    </div>
                  </div>
                  <div className="flex items-start space-x-2">
                    <Checkbox
                      id="org_mail"
                      checked={watch('org_mail')}
                      onCheckedChange={(checked) => setValue('org_mail', !!checked)}
                    />
                    <div>
                      <label htmlFor="org_mail" className="text-sm cursor-pointer">
                        {t('notificationChannels.emailOrgMail')}
                      </label>
                      <p className="text-xs text-muted-foreground">
                        {t('notificationChannels.emailOrgMailHelp')}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {selectedProvider?.id === 'telegram' && (
                <div className="space-y-2">
                  <Label htmlFor="channel_id">
                    {t('notifications.dialog.chatId', 'Chat ID')}{' '}
                    <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id="channel_id"
                    placeholder={t(
                      'notifications.dialog.chatIdPlaceholder',
                      'e.g., -1001274567890 or @channelname'
                    )}
                    {...register('channel_id', { required: selectedProvider?.id === 'telegram' })}
                  />
                  {errors.channel_id && (
                    <p className="text-sm text-destructive">
                      {t('notifications.dialog.chatIdRequired', 'Chat ID is required for Telegram')}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'notifications.dialog.chatIdHelpAdd',
                      'Get your chat ID: 1) Add @userinfobot to your group or channel, 2) It will reply with the chat ID. For groups or channels, use the numeric ID (e.g., -1001274567890).'
                    )}
                  </p>
                </div>
              )}

              {(selectedProvider?.provider === 'slack' ||
                selectedProvider?.provider === 'teams') && (
                <div className="space-y-2">
                  <Label htmlFor="channel_name">
                    {t('notifications.dialog.channelName', 'Channel name (optional)')}
                  </Label>
                  <Input
                    id="channel_name"
                    placeholder={t(
                      'notifications.dialog.channelNamePlaceholder',
                      'e.g., security-alerts'
                    )}
                    {...register('channel_name')}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t('notifications.dialog.channelNameHelp', 'Display name for reference')}
                  </p>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="description">
                  {t('notifications.dialog.description', 'Description (optional)')}
                </Label>
                <Textarea
                  id="description"
                  placeholder={t(
                    'notifications.dialog.descriptionPlaceholder',
                    'Describe the purpose of this channel...'
                  )}
                  className="resize-none"
                  {...register('description')}
                />
              </div>

              <div className="space-y-3">
                <Label>{t('notifications.dialog.severityFilters', 'Severity filters')}</Label>
                <p className="text-xs text-muted-foreground">
                  {t(
                    'notifications.dialog.severityFiltersHelp',
                    'Select which severity levels should trigger notifications'
                  )}
                </p>
                <div className="grid grid-cols-3 gap-3">
                  {ALL_NOTIFICATION_SEVERITIES.map((severity) => {
                    const enabledSeverities = watch('enabled_severities')
                    const isChecked = enabledSeverities.includes(severity.value)
                    const colorClass =
                      SEVERITY_TEXT_COLORS[
                        (severity.value === 'none' ? 'info' : severity.value) as SeverityLevel
                      ]
                    return (
                      <div key={severity.value} className="flex items-center space-x-2">
                        <Checkbox
                          id={`severity_${severity.value}`}
                          checked={isChecked}
                          onCheckedChange={(checked) => {
                            if (checked) {
                              setValue('enabled_severities', [...enabledSeverities, severity.value])
                            } else {
                              setValue(
                                'enabled_severities',
                                enabledSeverities.filter(
                                  (s: NotificationSeverity) => s !== severity.value
                                )
                              )
                            }
                          }}
                        />
                        <label
                          htmlFor={`severity_${severity.value}`}
                          className={cn('text-sm font-normal cursor-pointer', colorClass)}
                        >
                          {severity.label}
                        </label>
                      </div>
                    )
                  })}
                </div>
                {errors.enabled_severities && (
                  <p className="text-sm text-destructive">{errors.enabled_severities.message}</p>
                )}
              </div>

              <EventTypeSelector
                eventTypes={availableEventTypes}
                categories={eventCategories}
                value={watch('enabled_event_types')}
                onChange={(next) => setValue('enabled_event_types', next)}
                idPrefix="event"
                isLoading={eventTypesLoading}
                error={eventTypesError}
              />

              {errors.enabled_event_types && (
                <p className="text-sm text-destructive">{errors.enabled_event_types.message}</p>
              )}

              {/* Advanced Settings */}
              <Collapsible open={advancedOpen} onOpenChange={setAdvancedOpen}>
                <CollapsibleTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    className="flex w-full items-center justify-between p-0 h-auto hover:bg-transparent"
                  >
                    <div className="flex items-center gap-2 text-sm font-medium">
                      <Settings2 className="h-4 w-4" />
                      {t('notifications.dialog.advancedSettings', 'Advanced settings')}
                    </div>
                    <ChevronDown
                      className={cn('h-4 w-4 transition-transform', advancedOpen && 'rotate-180')}
                    />
                  </Button>
                </CollapsibleTrigger>
                <CollapsibleContent className="space-y-4 pt-4">
                  <ChannelMessageSettings
                    idPrefix="add"
                    detailLevel={watch('detail_level')}
                    onDetailLevelChange={(level) =>
                      setValue('detail_level', level, { shouldDirty: true })
                    }
                    template={watch('message_template') || ''}
                    onTemplateChange={(v) => setValue('message_template', v, { shouldDirty: true })}
                  />

                  <ChannelGroupingSettings
                    idPrefix="add"
                    value={{
                      group_similar: watch('group_similar'),
                      group_window_minutes: watch('group_window_minutes'),
                      urgent_at_once: watch('urgent_at_once'),
                    }}
                    onChange={(next) => {
                      if (next.group_similar !== undefined)
                        setValue('group_similar', next.group_similar, { shouldDirty: true })
                      if (next.group_window_minutes !== undefined)
                        setValue('group_window_minutes', next.group_window_minutes, {
                          shouldDirty: true,
                        })
                      if (next.urgent_at_once !== undefined)
                        setValue('urgent_at_once', next.urgent_at_once, { shouldDirty: true })
                    }}
                  />
                </CollapsibleContent>
              </Collapsible>
            </DialogBody>

            <DialogFooter className="sm:justify-between">
              <Button type="button" variant="outline" onClick={handleBack}>
                {t('notifications.dialog.back', 'Back')}
              </Button>
              <Button type="submit" disabled={isMutating}>
                {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {t('notifications.dialog.create', 'Create channel')}
              </Button>
            </DialogFooter>
          </DialogForm>
        )}
      </DialogContent>
    </Dialog>
  )
}
