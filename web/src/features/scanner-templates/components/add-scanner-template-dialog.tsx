'use client'

import * as React from 'react'
import { useState, useCallback } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2, Upload, FileCode2, AlertTriangle, CheckCircle } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'

import {
  useCreateScannerTemplate,
  useValidateScannerTemplate,
  invalidateScannerTemplatesCache,
} from '@/lib/api/scanner-template-hooks'
import type { TemplateType, TemplateValidationResult } from '@/lib/api/scanner-template-types'
import {
  TEMPLATE_TYPES,
  TEMPLATE_TYPE_DISPLAY_NAMES,
  TEMPLATE_TYPE_DESCRIPTIONS,
  TEMPLATE_TYPE_EXTENSIONS,
  TEMPLATE_TYPE_MAX_SIZES,
  encodeTemplateContent,
  formatTemplateSize,
} from '@/lib/api/scanner-template-types'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'

// Form schema
type Translate = ReturnType<typeof useTranslation>['t']

const buildFormSchema = (t: Translate) =>
  z.object({
    name: z
      .string()
      .min(1, t('scans.templates.add.nameRequired', 'Name is required'))
      .max(255, t('scans.templates.add.nameTooLong', 'Name is too long')),
    template_type: z.enum(TEMPLATE_TYPES, {
      message: t('scans.templates.add.typeRequired', 'Template type is required'),
    }),
    description: z
      .string()
      .max(1000, t('scans.templates.add.descriptionTooLong', 'Description is too long'))
      .optional(),
    content: z
      .string()
      .min(1, t('scans.templates.add.contentRequired', 'Template content is required')),
    tags: z.string().optional(),
  })

type FormValues = z.infer<ReturnType<typeof buildFormSchema>>

interface AddScannerTemplateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

export function AddScannerTemplateDialog({
  open,
  onOpenChange,
  onSuccess,
}: AddScannerTemplateDialogProps) {
  const { t } = useTranslation()
  const [validationResult, setValidationResult] = useState<TemplateValidationResult | null>(null)
  const [isValidating, setIsValidating] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)

  const { trigger: createTemplate, isMutating: isCreating } = useCreateScannerTemplate()
  const { trigger: validateTemplate } = useValidateScannerTemplate()

  const form = useForm<FormValues>({
    resolver: zodResolver(buildFormSchema(t)),
    defaultValues: {
      name: '',
      template_type: undefined,
      description: '',
      content: '',
      tags: '',
    },
  })

  const selectedType = form.watch('template_type')
  const content = form.watch('content')

  // Reset form when dialog closes
  React.useEffect(() => {
    if (!open) {
      form.reset()
      setValidationResult(null)
      setFileName(null)
    }
  }, [open, form])

  // Validate content
  const validateContent = useCallback(
    async (content: string, type: TemplateType) => {
      if (!content || !type) return

      setIsValidating(true)
      try {
        const result = await validateTemplate({
          template_type: type,
          content: encodeTemplateContent(content),
        })
        setValidationResult(result ?? null)
      } catch (_err) {
        setValidationResult({
          valid: false,
          errors: [
            {
              field: 'content',
              message: t('scans.templates.add.validateFailed', 'Failed to validate template'),
              code: 'VALIDATION_ERROR',
            },
          ],
          rule_count: 0,
        })
      } finally {
        setIsValidating(false)
      }
    },
    [validateTemplate, t]
  )

  // Handle file upload
  const handleFileUpload = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (!file) return

      // Check file size
      const type = selectedType as TemplateType
      if (type && file.size > TEMPLATE_TYPE_MAX_SIZES[type]) {
        toast.error(
          t(
            'scans.templates.add.fileTooLarge',
            'File too large. Maximum size for {type} is {size}',
            {
              type: TEMPLATE_TYPE_DISPLAY_NAMES[type],
              size: formatTemplateSize(TEMPLATE_TYPE_MAX_SIZES[type]),
            }
          )
        )
        return
      }

      // Read file content
      const reader = new FileReader()
      reader.onload = async (event) => {
        const text = event.target?.result as string
        form.setValue('content', text)
        setFileName(file.name)

        // Auto-fill name if empty
        if (!form.getValues('name')) {
          const baseName = file.name.replace(/\.(yaml|yml|toml)$/i, '')
          form.setValue('name', baseName)
        }

        // Auto-validate
        if (selectedType) {
          await validateContent(text, selectedType)
        }
      }
      reader.readAsText(file)
    },
    [form, selectedType, validateContent, t]
  )

  // Handle type change
  const handleTypeChange = useCallback(
    async (type: TemplateType) => {
      form.setValue('template_type', type)
      if (content) {
        await validateContent(content, type)
      }
    },
    [form, content, validateContent]
  )

  // Submit form
  const onSubmit = useCallback(
    async (values: FormValues) => {
      // Require validation before submit
      if (!validationResult?.valid) {
        toast.error(
          t('scans.templates.add.fixErrors', 'Please fix validation errors before uploading')
        )
        return
      }

      try {
        await createTemplate({
          name: values.name,
          template_type: values.template_type,
          description: values.description || undefined,
          content: encodeTemplateContent(values.content),
          tags: values.tags
            ? values.tags
                .split(',')
                .map((t) => t.trim())
                .filter(Boolean)
            : undefined,
        })

        toast.success(
          t('scans.templates.add.created', 'Template "{name}" created successfully', {
            name: values.name,
          })
        )
        await invalidateScannerTemplatesCache()
        onOpenChange(false)
        onSuccess?.()
      } catch (err) {
        toast.error(
          getErrorMessage(err, t('scans.templates.add.createFailed', 'Failed to create template'))
        )
      }
    },
    [createTemplate, validationResult, onOpenChange, onSuccess, t]
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileCode2 className="h-5 w-5" />
            {t('scans.templates.add.title', 'Upload scanner template')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'scans.templates.add.description',
              'Upload a custom template for Nuclei, Semgrep, or Betterleaks scanners.'
            )}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <DialogForm onSubmit={form.handleSubmit(onSubmit)}>
            {/* Template Type */}
            <DialogBody className="space-y-4">
              <FormField
                control={form.control}
                name="template_type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('scans.templates.add.type', 'Template type')}</FormLabel>
                    <Select
                      onValueChange={(v) => handleTypeChange(v as TemplateType)}
                      value={field.value}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue
                            placeholder={t(
                              'scans.templates.add.typePlaceholder',
                              'Select a scanner type'
                            )}
                          />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {TEMPLATE_TYPES.map((type) => (
                          <SelectItem key={type} value={type}>
                            <div className="flex flex-col">
                              <span>{TEMPLATE_TYPE_DISPLAY_NAMES[type]}</span>
                              <span className="text-xs text-muted-foreground">
                                {t(
                                  `scans.templates.add.typeDesc.${type}`,
                                  TEMPLATE_TYPE_DESCRIPTIONS[type]
                                )}
                              </span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Name */}
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('scans.templates.add.name', 'Name')}</FormLabel>
                    <FormControl>
                      <Input placeholder="my-custom-template" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Description */}
              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      {t('scans.templates.add.descriptionLabel', 'Description')}
                    </FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder={t(
                          'scans.templates.add.descriptionPlaceholder',
                          'A brief description of what this template detects...'
                        )}
                        className="resize-none"
                        rows={2}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* File Upload */}
              <FormField
                control={form.control}
                name="content"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('scans.templates.add.file', 'Template file')}</FormLabel>
                    <FormControl>
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <Input
                            type="file"
                            accept={
                              selectedType
                                ? TEMPLATE_TYPE_EXTENSIONS[selectedType]
                                : '.yaml,.yml,.toml'
                            }
                            onChange={handleFileUpload}
                            className="hidden"
                            id="template-file"
                            disabled={!selectedType}
                          />
                          <Button
                            type="button"
                            variant="outline"
                            disabled={!selectedType}
                            onClick={() => document.getElementById('template-file')?.click()}
                          >
                            <Upload className="me-2 h-4 w-4" />
                            {t('scans.templates.add.chooseFile', 'Choose file')}
                          </Button>
                          {fileName && (
                            <span className="text-sm text-muted-foreground">{fileName}</span>
                          )}
                        </div>
                        {selectedType && (
                          <FormDescription>
                            {t('scans.templates.add.accepted', 'Accepted: {ext} (max {size})', {
                              ext: TEMPLATE_TYPE_EXTENSIONS[selectedType],
                              size: formatTemplateSize(TEMPLATE_TYPE_MAX_SIZES[selectedType]),
                            })}
                          </FormDescription>
                        )}
                        {field.value && (
                          <Textarea
                            placeholder={t(
                              'scans.templates.add.pastePlaceholder',
                              'Or paste template content here...'
                            )}
                            className="font-mono text-sm"
                            rows={6}
                            value={field.value}
                            onChange={(e) => {
                              field.onChange(e.target.value)
                              setFileName(null)
                              setValidationResult(null)
                            }}
                          />
                        )}
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Tags */}
              <FormField
                control={form.control}
                name="tags"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('scans.templates.add.tags', 'Tags (optional)')}</FormLabel>
                    <FormControl>
                      <Input placeholder="sqli, owasp, web" {...field} />
                    </FormControl>
                    <FormDescription>
                      {t('scans.templates.add.tagsHint', 'Comma-separated tags for filtering')}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Validation Result */}
              {isValidating && (
                <Alert>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <AlertTitle>{t('scans.templates.add.validating', 'Validating...')}</AlertTitle>
                  <AlertDescription>
                    {t(
                      'scans.templates.add.validatingHint',
                      'Checking template syntax and structure'
                    )}
                  </AlertDescription>
                </Alert>
              )}

              {validationResult &&
                !isValidating &&
                (validationResult.valid ? (
                  <Alert className="border-success/30 bg-success/10">
                    <CheckCircle className="h-4 w-4 text-success" />
                    <AlertTitle className="text-success">
                      {t('scans.templates.add.valid', 'Valid template')}
                    </AlertTitle>
                    <AlertDescription>
                      {validationResult.rule_count === 1
                        ? t('scans.templates.add.foundOne', 'Found {count} rule', {
                            count: validationResult.rule_count,
                          })
                        : t('scans.templates.add.foundMany', 'Found {count} rules', {
                            count: validationResult.rule_count,
                          })}
                    </AlertDescription>
                  </Alert>
                ) : (
                  // submit-error-ok: the result of the Validate button, not a failed submit
                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>{t('scans.templates.add.errors', 'Validation errors')}</AlertTitle>
                    <AlertDescription>
                      <ul className="mt-2 list-inside list-disc">
                        {validationResult.errors?.map((error, i) => (
                          <li key={i}>
                            {error.field}: {error.message}
                          </li>
                        ))}
                      </ul>
                    </AlertDescription>
                  </Alert>
                ))}
            </DialogBody>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isCreating}
              >
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={isCreating || !validationResult?.valid}>
                {isCreating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {t('scans.templates.upload', 'Upload template')}
              </Button>
            </DialogFooter>
          </DialogForm>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
