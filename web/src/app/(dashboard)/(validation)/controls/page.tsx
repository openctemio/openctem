'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import useSWR from 'swr'
import { Main } from '@/components/layout'
import { PageHeader, DataTable, DataTableColumnHeader, EmptyState } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Plus, Trash2, FlaskConical, Link2, ShieldCheck } from 'lucide-react'
import { get, post, del } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission } from '@/lib/permissions'
import { toast } from 'sonner'
import { LinkAssetsDialog } from '@/features/controls/components/link-assets-dialog'
import {
  CONTROL_TYPES,
  MAX_REDUCTION_PERCENT,
  MIN_REDUCTION_PERCENT,
  TEST_RESULTS,
  factorToPercent,
  humanizeControlValue,
  isValidReductionPercent,
  percentToFactor,
  type ControlStatus,
  type ControlType,
  type TestResult,
} from '@/features/controls/vocabulary'
import { useTranslation } from '@/context/i18n-provider'
import { formatDateSafe } from '@/lib/format-date'

interface CompensatingControl {
  id: string
  name: string
  description: string
  control_type: ControlType
  status: ControlStatus
  reduction_factor: number
  last_tested_at: string | null
  test_result: TestResult | null
  created_at: string
  updated_at: string
}

interface PaginatedResponse {
  data: CompensatingControl[]
  total: number
  page: number
  per_page: number
}

// Theme tokens only: the problem states (expired, a failed test) are the only
// ones coloured; the rest read as neutral status.
const statusVariant: Record<string, { variant: 'secondary' | 'outline'; className?: string }> = {
  active: { variant: 'secondary' },
  inactive: { variant: 'outline', className: 'text-muted-foreground' },
  expired: { variant: 'outline', className: 'text-destructive' },
  untested: { variant: 'outline', className: 'text-muted-foreground' },
}

const testResultVariant: Record<string, { variant: 'secondary' | 'outline'; className?: string }> =
  {
    pass: { variant: 'secondary' },
    fail: { variant: 'outline', className: 'text-destructive' },
    partial: { variant: 'outline' },
  }

export default function CompensatingControlsPage() {
  const { t } = useTranslation()
  const {
    data: response,
    isLoading,
    mutate,
  } = useSWR<PaginatedResponse>('/api/v1/compensating-controls?per_page=100', get, {
    revalidateOnFocus: false,
  })

  const controls = response?.data ?? []

  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [testControlId, setTestControlId] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<TestResult>('pass')
  const [deleteControl, setDeleteControl] = useState<CompensatingControl | null>(null)
  const [linkControl, setLinkControl] = useState<CompensatingControl | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    control_type: 'runtime' as ControlType,
    // Percent as the operator types it; converted to the 0-1 fraction the API
    // stores at the boundary in handleCreate.
    reduction_percent: '20',
  })

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      control_type: 'runtime',
      reduction_percent: '20',
    })
  }

  const handleCreate = async () => {
    if (!formData.name.trim()) {
      toast.error(t('validation.controls.nameRequired', 'Enter a control name.'))
      return
    }
    const percent = Number(formData.reduction_percent)
    if (!isValidReductionPercent(percent)) {
      toast.error(
        t(
          'validation.controls.reductionRange',
          'Reduction must be between 1% and 100%. A 0% control would have no effect.'
        )
      )
      return
    }
    setIsCreating(true)
    try {
      await post('/api/v1/compensating-controls', {
        name: formData.name.trim(),
        description: formData.description,
        control_type: formData.control_type,
        // The API takes a fraction (DECIMAL(3,2), CHECK 0..1), not a percent.
        reduction_factor: percentToFactor(percent),
      })
      await mutate()
      toast.success(
        t(
          'validation.controls.created',
          'Compensating control created. Link assets to make it reduce their priority.'
        )
      )
      setIsCreateOpen(false)
      resetForm()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('validation.controls.createFailed', 'Failed to create control'))
      )
    } finally {
      setIsCreating(false)
    }
  }

  const handleRecordTest = async () => {
    if (!testControlId) return
    try {
      // POST, not PATCH — the route is registered as POST /{id}/test and a
      // PATCH returned 405, so recording a test never worked.
      await post(`/api/v1/compensating-controls/${testControlId}/test`, {
        test_result: testResult,
      })
      await mutate()
      toast.success(
        testResult === 'fail'
          ? t(
              'validation.controls.testRecordedFail',
              'Test result recorded. A failed control is deactivated and stops reducing priority.'
            )
          : t('validation.controls.testRecorded', 'Test result recorded')
      )
      setTestControlId(null)
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('validation.controls.recordFailed', 'Failed to record test result')
        )
      )
    }
  }

  const handleDelete = async () => {
    if (!deleteControl) return
    try {
      await del(`/api/v1/compensating-controls/${deleteControl.id}`)
      await mutate()
      toast.success(t('validation.controls.deleted', 'Control deleted'))
      setDeleteControl(null)
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('validation.controls.deleteFailed', 'Failed to delete control'))
      )
    }
  }

  const columns = useMemo<ColumnDef<CompensatingControl>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('validation.controls.col.name', 'Name')}
          />
        ),
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        accessorKey: 'control_type',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('validation.controls.col.type', 'Type')}
          />
        ),
        cell: ({ row }) => (
          <Badge variant="outline">
            {t(
              `validation.controls.type.${row.original.control_type}`,
              humanizeControlValue(row.original.control_type)
            )}
          </Badge>
        ),
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('validation.controls.col.status', 'Status')}
          />
        ),
        cell: ({ row }) => {
          const v = statusVariant[row.original.status] ?? { variant: 'outline' as const }
          return (
            <Badge variant={v.variant} className={v.className}>
              {t(
                `validation.controls.status.${row.original.status}`,
                humanizeControlValue(row.original.status)
              )}
            </Badge>
          )
        },
      },
      {
        accessorKey: 'reduction_factor',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('validation.controls.col.reduction', 'Reduction')}
          />
        ),
        // The API stores a 0-1 fraction; render it as the percent the form
        // accepts. Previously the raw fraction was suffixed with "%", so a
        // stored 0.30 displayed as "0.3%".
        cell: ({ row }) => (
          <span className="text-sm tabular-nums">
            {factorToPercent(row.original.reduction_factor)}%
          </span>
        ),
      },
      {
        accessorKey: 'last_tested_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('validation.controls.col.lastTested', 'Last tested')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {row.original.last_tested_at
              ? formatDateSafe(row.original.last_tested_at)
              : t('validation.controls.never', 'Never')}
          </span>
        ),
      },
      {
        accessorKey: 'test_result',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('validation.controls.col.testResult', 'Test result')}
          />
        ),
        cell: ({ row }) =>
          row.original.test_result ? (
            <Badge
              variant={testResultVariant[row.original.test_result]?.variant ?? 'outline'}
              className={testResultVariant[row.original.test_result]?.className}
            >
              {t(
                `validation.controls.result.${row.original.test_result}`,
                humanizeControlValue(row.original.test_result)
              )}
            </Badge>
          ) : (
            <span className="text-sm text-muted-foreground">—</span>
          ),
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const control = row.original
          return (
            <Can permission={Permission.CompensatingControlsWrite}>
              <div className="flex items-center justify-end gap-1">
                <Button variant="ghost" size="sm" onClick={() => setLinkControl(control)}>
                  <Link2 className="me-1 h-3 w-3" />
                  {t('validation.controls.linkAssets', 'Link assets')}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setTestControlId(control.id)
                    setTestResult('pass')
                  }}
                >
                  <FlaskConical className="me-1 h-3 w-3" />
                  {t('validation.controls.test', 'Test')}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setDeleteControl(control)}
                  className="text-destructive"
                  aria-label={t('validation.controls.deleteAria', 'Delete {name}', {
                    name: control.name,
                  })}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </Can>
          )
        },
      },
    ],
    [t]
  )

  return (
    <>
      <Main>
        <PageHeader
          title={t('validation.controls.title', 'Compensating controls')}
          description={t(
            'validation.controls.description',
            'Controls that hold down the priority of findings on the assets they protect.'
          )}
        >
          <Can permission={Permission.CompensatingControlsWrite}>
            <Button size="sm" onClick={() => setIsCreateOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('validation.controls.new', 'New control')}
            </Button>
          </Can>
        </PageHeader>

        <div className="mt-5">
          {isLoading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : controls.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              title={t('validation.controls.emptyTitle', 'No compensating controls yet')}
              description={t(
                'validation.controls.emptyDesc',
                'Create a control, then link the assets it protects.'
              )}
            />
          ) : (
            <DataTable
              columns={columns}
              data={controls}
              searchPlaceholder={t('validation.controls.searchPlaceholder', 'Search controls…')}
            />
          )}
        </div>
      </Main>

      {/* Create Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('validation.controls.createTitle', 'New compensating control')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'validation.controls.createDesc',
                'Add a control that reduces finding risk scores.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">{t('validation.controls.field.name', 'Name *')}</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder={t(
                    'validation.controls.field.namePlaceholder',
                    'e.g., WAF rate limiting'
                  )}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">
                  {t('validation.controls.field.description', 'Description')}
                </Label>
                <Input
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder={t(
                    'validation.controls.field.descriptionPlaceholder',
                    'What this control does'
                  )}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="control_type">
                    {t('validation.controls.field.type', 'Control type')}
                  </Label>
                  <Select
                    value={formData.control_type}
                    onValueChange={(value) =>
                      setFormData({
                        ...formData,
                        control_type: value as ControlType,
                      })
                    }
                  >
                    <SelectTrigger id="control_type">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {/* Driven from the shared vocabulary so the form cannot
                        offer a value the backend rejects. */}
                      {CONTROL_TYPES.map((type) => (
                        <SelectItem key={type.value} value={type.value}>
                          {t(`validation.controls.type.${type.value}`, type.label)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="reduction_percent">
                    {t('validation.controls.field.reduction', 'Risk reduction (%)')}
                  </Label>
                  <Input
                    id="reduction_percent"
                    type="number"
                    min={MIN_REDUCTION_PERCENT}
                    max={MAX_REDUCTION_PERCENT}
                    value={formData.reduction_percent}
                    onChange={(e) =>
                      setFormData({ ...formData, reduction_percent: e.target.value })
                    }
                  />
                </div>
              </div>
              <p className="text-muted-foreground text-xs">
                {t(
                  'validation.controls.capHint',
                  'Findings on the linked assets are held at P2 rather than P1. The percentage is shown as the rationale only.'
                )}
              </p>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreate} disabled={isCreating}>
              {isCreating
                ? t('validation.controls.creating', 'Creating…')
                : t('validation.controls.create', 'Create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Record Test Dialog */}
      <Dialog open={!!testControlId} onOpenChange={(open) => !open && setTestControlId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('validation.controls.recordTitle', 'Record test result')}</DialogTitle>
            <DialogDescription>
              {t(
                'validation.controls.recordDesc',
                'Record the result of a control effectiveness test.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="test_result">
                  {t('validation.controls.field.testResult', 'Test result')}
                </Label>
                <Select
                  value={testResult}
                  onValueChange={(v) => setTestResult(v as typeof testResult)}
                >
                  <SelectTrigger id="test_result">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TEST_RESULTS.map((result) => (
                      <SelectItem key={result} value={result}>
                        {t(`validation.controls.result.${result}`, humanizeControlValue(result))}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {testResult === 'fail' && (
                <p className="text-muted-foreground text-xs">
                  {t(
                    'validation.controls.failHint',
                    'Recording a failure deactivates this control. It will stop reducing the priority of findings on its linked assets.'
                  )}
                </p>
              )}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTestControlId(null)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleRecordTest}>{t('validation.controls.record', 'Record')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Link Assets — the only action that makes a control affect scoring */}
      <LinkAssetsDialog
        control={linkControl}
        onOpenChange={(open) => !open && setLinkControl(null)}
        onLinked={() => {
          void mutate()
        }}
      />

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteControl}
        onOpenChange={(open) => !open && setDeleteControl(null)}
        title={t('confirm.control.deleteTitle', 'Delete the control "{name}"?', {
          name: deleteControl?.name ?? '',
        })}
        desc={t('confirm.control.deleteDesc', 'This cannot be undone.')}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        handleConfirm={handleDelete}
      />
    </>
  )
}
