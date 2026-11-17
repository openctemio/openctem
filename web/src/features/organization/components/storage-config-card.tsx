'use client'

import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useState,
  type ReactNode,
} from 'react'
import { AlertCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  SecretField,
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsSection,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { get, patch } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate } from '@/lib/permissions'

interface StorageValues {
  provider: string
  bucket: string
  region: string
  endpoint: string
}

const LOCAL: StorageValues = { provider: 'local', bucket: '', region: '', endpoint: '' }

/** What the page's save bar needs to know about the storage form. */
export interface StorageFormState {
  /** The form differs from what is stored. */
  dirty: boolean
  /** A required field is empty: the page's Save stays off. */
  invalid: boolean
  saving: boolean
}

export interface StorageConfigHandle {
  /** Saves when dirty and valid. Resolves false when the save failed (the changes are kept). */
  save: () => Promise<boolean>
  discard: () => void
}

interface StorageConfigSectionProps {
  /** Reports dirty / invalid / saving to the page, which owns the one save bar. */
  onStateChange?: (state: StorageFormState) => void
}

/**
 * Organization › General › File storage: where uploaded evidence and
 * attachments are kept (admin only, PATCH /attachments/storage-config with a
 * recent sign-in). The stored keys are never read back: the access and
 * secret key fields are write-only and empty means "keep the stored ones".
 *
 * A section of the General page: it has no save button of its own. The page's
 * save bar saves it through the handle, with the organization form.
 */
export const StorageConfigSection = forwardRef<StorageConfigHandle, StorageConfigSectionProps>(
  function StorageConfigSection({ onStateChange }, ref) {
    const { t } = useTranslation()
    const canSave = useCanMutate('PATCH /api/v1/attachments/storage-config')
    const [saved, setSaved] = useState<StorageValues>(LOCAL)
    const [values, setValues] = useState<StorageValues>(LOCAL)
    const [accessKey, setAccessKey] = useState('')
    const [secretKey, setSecretKey] = useState('')
    const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
    const [loadError, setLoadError] = useState<string>()
    const [saving, setSaving] = useState(false)
    // Required fields complain only after a save was tried or the field was left.
    const [touched, setTouched] = useState(false)

    const load = useCallback(() => {
      setState('loading')
      get('/api/v1/attachments/storage-config')
        .then((data: unknown) => {
          const d = (data ?? {}) as Record<string, unknown>
          const next: StorageValues = d.configured
            ? {
                provider: (d.provider as string) || 'local',
                bucket: (d.bucket as string) || '',
                region: (d.region as string) || '',
                endpoint: (d.endpoint as string) || '',
              }
            : LOCAL
          setSaved(next)
          setValues(next)
          setState('ready')
        })
        .catch((err: unknown) => {
          // Never fall back to "local" as if that were the stored choice.
          setLoadError(getErrorMessage(err, ''))
          setState('error')
        })
    }, [])

    useEffect(() => {
      load()
    }, [load])

    const isCloud = values.provider === 's3' || values.provider === 'minio'
    const dirty =
      state === 'ready' &&
      (JSON.stringify(values) !== JSON.stringify(saved) || accessKey !== '' || secretKey !== '')
    const bucketMissing = isCloud && !values.bucket.trim()
    const endpointMissing = values.provider === 'minio' && !values.endpoint.trim()
    const invalid = bucketMissing || endpointMissing

    useEffect(() => {
      onStateChange?.({ dirty, invalid, saving })
    }, [onStateChange, dirty, invalid, saving])

    const discard = useCallback(() => {
      setValues(saved)
      setAccessKey('')
      setSecretKey('')
      setTouched(false)
    }, [saved])

    const save = useCallback(async (): Promise<boolean> => {
      if (!dirty) return true
      if (invalid) {
        setTouched(true)
        return false
      }
      setSaving(true)
      try {
        await patch('/api/v1/attachments/storage-config', {
          ...values,
          access_key: accessKey,
          secret_key: secretKey,
        })
        toast.success(t('org.storage.saved', 'File storage saved'))
        setSaved(values)
        setAccessKey('')
        setSecretKey('')
        setTouched(false)
        return true
      } catch (err) {
        toast.error(
          getErrorMessage(err, t('org.storage.saveFailed', 'Could not save the file storage'))
        )
        return false
      } finally {
        setSaving(false)
      }
    }, [dirty, invalid, values, accessKey, secretKey, t])

    useImperativeHandle(ref, () => ({ save, discard }), [save, discard])

    const disabled = !canSave
    const frame = (body: ReactNode) => (
      <SettingsSection
        framed
        id="storage"
        title={t('org.general.tab.storage', 'File storage')}
        description={
          <>
            {t('org.storage.desc', 'Where uploaded evidence and attachments are stored.')}
            {disabled && ` ${t('org.storage.locked', 'Only administrators can change it.')}`}
          </>
        }
      >
        {body}
      </SettingsSection>
    )

    if (state === 'loading') {
      return frame(
        <SettingsBlock>
          <Skeleton className="h-8 w-72 max-w-full" />
        </SettingsBlock>
      )
    }
    if (state === 'error') {
      return frame(
        <SettingsBlock>
          <Alert variant="destructive">
            <AlertCircle aria-hidden />
            <AlertTitle>
              {t('org.storage.loadFailed', 'The file storage settings could not be loaded')}
            </AlertTitle>
            <AlertDescription>
              {loadError && <p>{loadError}</p>}
              <Button variant="outline" className="mt-2" onClick={load}>
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        </SettingsBlock>
      )
    }

    const set = (k: keyof StorageValues) => (v: string) => setValues((p) => ({ ...p, [k]: v }))
    const required = t('org.storage.required', 'Required')

    return frame(
      <SettingsBlock>
        <SettingsFieldGrid>
          <SettingsField
            id="storage-provider"
            className="max-w-sm"
            label={t('org.storage.provider', 'Provider')}
            hint={
              isCloud
                ? undefined
                : t(
                    'org.storage.localHelp',
                    'Files are stored on the server disk at the default storage path.'
                  )
            }
          >
            {(control) => (
              <Select value={values.provider} onValueChange={set('provider')} disabled={disabled}>
                <SelectTrigger {...control} className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="local">
                    {t('org.storage.local', 'Local filesystem')}
                  </SelectItem>
                  <SelectItem value="s3">Amazon S3</SelectItem>
                  <SelectItem value="minio">
                    {t('org.storage.minio', 'MinIO (S3-compatible)')}
                  </SelectItem>
                </SelectContent>
              </Select>
            )}
          </SettingsField>
        </SettingsFieldGrid>

        {isCloud && (
          <>
            <SettingsFieldGrid>
              <SettingsField
                id="storage-bucket"
                label={t('org.storage.bucket', 'Bucket name')}
                error={touched && bucketMissing ? required : undefined}
              >
                {(control) => (
                  <Input
                    {...control}
                    required
                    value={values.bucket}
                    onChange={(e) => set('bucket')(e.target.value)}
                    onBlur={() => setTouched(true)}
                    placeholder="my-evidence-bucket"
                    disabled={disabled}
                  />
                )}
              </SettingsField>
              <SettingsField id="storage-region" label={t('org.storage.region', 'Region')}>
                {(control) => (
                  <Input
                    {...control}
                    value={values.region}
                    onChange={(e) => set('region')(e.target.value)}
                    placeholder="ap-southeast-1"
                    disabled={disabled}
                  />
                )}
              </SettingsField>
              {values.provider === 'minio' && (
                <SettingsField
                  id="storage-endpoint"
                  label={t('org.storage.endpoint', 'Endpoint')}
                  error={touched && endpointMissing ? required : undefined}
                >
                  {(control) => (
                    <Input
                      {...control}
                      required
                      type="url"
                      value={values.endpoint}
                      onChange={(e) => set('endpoint')(e.target.value)}
                      onBlur={() => setTouched(true)}
                      placeholder="https://storage.example.com:9000"
                      disabled={disabled}
                    />
                  )}
                </SettingsField>
              )}
              <SettingsField
                id="storage-access-key"
                label={t('org.storage.accessKey', 'Access key')}
              >
                {(control) => (
                  <SecretField
                    {...control}
                    stored
                    value={accessKey}
                    onChange={(e) => setAccessKey(e.target.value)}
                    disabled={disabled}
                  />
                )}
              </SettingsField>
              <SettingsField
                id="storage-secret-key"
                label={t('org.storage.secretKey', 'Secret key')}
                hint={t(
                  'org.storage.keysHelp',
                  'The stored keys are never shown. Leave both empty to keep them.'
                )}
              >
                {(control) => (
                  <SecretField
                    {...control}
                    stored
                    value={secretKey}
                    onChange={(e) => setSecretKey(e.target.value)}
                    disabled={disabled}
                  />
                )}
              </SettingsField>
            </SettingsFieldGrid>
            <p className="max-w-[58ch] text-dense text-muted-foreground text-pretty">
              {t(
                'org.storage.switchNote',
                'Files already stored stay readable after a switch: each file remembers which provider holds it.'
              )}
            </p>
          </>
        )}
      </SettingsBlock>
    )
  }
)
