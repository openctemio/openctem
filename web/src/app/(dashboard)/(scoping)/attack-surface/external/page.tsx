'use client'

import { useState, useMemo, useEffect } from 'react'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useRouter } from 'next/navigation'
import {
  createAsset,
  updateAsset,
  deleteAsset as apiDeleteAsset,
  type CreateAssetInput,
  useAssets,
} from '@/features/assets'
import { Main } from '@/components/layout'
import { CRITICALITY_BADGE_SOFT } from '@/lib/criticality-colors'
import {
  PageHeader,
  DataTableRowActions,
  StatsCard,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Globe,
  Plus,
  Eye,
  Pencil,
  Trash2,
  ExternalLink,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Server,
  Lock,
  RefreshCw,
  Download,
  X,
  Search as SearchIcon,
  ArrowUpRight,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { toast } from 'sonner'
import { Can, Permission, useHasPermission } from '@/lib/permissions'
import { exportToCsv } from '@/hooks/use-csv-export'
import { ScanAssetsDialog, type ScanCandidate } from '@/features/scans/components'

type AssetStatus = 'active' | 'inactive' | 'monitoring'
type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
type AssetType = 'domain' | 'subdomain' | 'service' | 'certificate'

interface ExternalAsset {
  id: string
  name: string
  type: AssetType
  parentDomain?: string
  ipAddress?: string
  port?: number
  status: AssetStatus
  riskLevel: RiskLevel
  sslExpiry?: string
  lastSeen: string
  discoveredAt: string
  findingsCount: number
  technologies?: string[]
  notes?: string
}

const statusColors: Record<AssetStatus, string> = {
  active: 'border-success/30 bg-success/10 text-success',
  inactive: 'border-border bg-muted text-muted-foreground',
  monitoring: 'border-info/30 bg-info/10 text-info',
}

// Risk shares the severity scale's soft colours.
const riskColors: Record<RiskLevel, string> = CRITICALITY_BADGE_SOFT

const typeIcons: Record<AssetType, React.ElementType> = {
  domain: Globe,
  subdomain: ArrowUpRight,
  service: Server,
  certificate: Lock,
}

export default function ExternalSurfacePage() {
  const router = useRouter()
  const canWriteScope = useHasPermission(Permission.ScopeWrite)
  // Fetch external assets from API
  const { assets: apiAssets, mutate: refetchAssets } = useAssets({
    types: ['domain', 'subdomain', 'service', 'ip_address'],
    scopes: ['external'],
    pageSize: 100,
  })
  const apiMapped = useMemo<ExternalAsset[]>(() => {
    if (!apiAssets || apiAssets.length === 0) return []
    return apiAssets.map((a): ExternalAsset => ({
      id: a.id,
      name: a.name,
      type: a.type as ExternalAsset['type'],
      ipAddress:
        (a.metadata?.ip_address as string) || (a.metadata?.resolved_ip as string) || undefined,
      status: a.status === 'active' ? 'active' : 'inactive',
      riskLevel:
        a.riskScore >= 70
          ? 'critical'
          : a.riskScore >= 50
            ? 'high'
            : a.riskScore >= 30
              ? 'medium'
              : 'low',
      lastSeen: a.updatedAt || a.createdAt,
      discoveredAt: a.createdAt,
      findingsCount: a.findingCount || 0,
      technologies: a.tags,
    }))
  }, [apiAssets])

  // Real external assets from the assets API; empty until data loads.
  const [assets, setAssets] = useState<ExternalAsset[]>([])
  useEffect(() => {
    setAssets(apiMapped)
  }, [apiMapped])
  const [searchQuery, setSearchQuery] = useState('')
  const [filterType, setFilterType] = useState<AssetType | 'all'>('all')
  const [filterRisk, setFilterRisk] = useState<RiskLevel | 'all'>('all')
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [viewAsset, setViewAsset] = useState<ExternalAsset | null>(null)
  const [editAsset, setEditAsset] = useState<ExternalAsset | null>(null)
  const [deleteAsset, setDeleteAsset] = useState<ExternalAsset | null>(null)
  const [scanCandidates, setScanCandidates] = useState<ScanCandidate[]>([])
  const [scanDialogOpen, setScanDialogOpen] = useState(false)

  const [formData, setFormData] = useState({
    name: '',
    type: 'subdomain' as AssetType,
    parentDomain: '',
    ipAddress: '',
    port: '',
    status: 'active' as AssetStatus,
    riskLevel: 'medium' as RiskLevel,
    notes: '',
  })

  // Use lazy state initialization for current time
  const [currentTime] = useState(() => Date.now())

  const stats = useMemo(() => {
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000
    return {
      total: assets.length,
      active: assets.filter((a) => a.status === 'active').length,
      critical: assets.filter((a) => a.riskLevel === 'critical').length,
      totalFindings: assets.reduce((acc, a) => acc + a.findingsCount, 0),
      expiringCerts: assets.filter((a) => {
        if (!a.sslExpiry) return false
        const expiryTime = new Date(a.sslExpiry).getTime()
        return expiryTime - currentTime <= thirtyDaysMs
      }).length,
    }
  }, [assets, currentTime])

  const filteredAssets = useMemo(() => {
    return assets.filter((asset) => {
      if (searchQuery && !asset.name.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false
      }
      if (filterType !== 'all' && asset.type !== filterType) return false
      if (filterRisk !== 'all' && asset.riskLevel !== filterRisk) return false
      return true
    })
  }, [assets, searchQuery, filterType, filterRisk])

  const resetForm = () => {
    setFormData({
      name: '',
      type: 'subdomain',
      parentDomain: '',
      ipAddress: '',
      port: '',
      status: 'active',
      riskLevel: 'medium',
      notes: '',
    })
  }

  const handleCreate = async () => {
    if (!formData.name) {
      toast.error('Please enter an asset name')
      return
    }
    // Persist through the real API. This previously only pushed onto local
    // state and reported success, so the asset vanished on the next reload —
    // the page reads from useAssets but the writes never reached it.
    try {
      await createAsset({
        name: formData.name,
        type: formData.type as CreateAssetInput['type'],
        scope: 'external',
        description: formData.notes || undefined,
        metadata: {
          ...(formData.ipAddress ? { ip_address: formData.ipAddress } : {}),
          ...(formData.port ? { port: Number(formData.port) } : {}),
          ...(formData.parentDomain ? { parent_domain: formData.parentDomain } : {}),
        },
      })
      toast.success('External asset added')
      setIsCreateOpen(false)
      resetForm()
      await refetchAssets()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Failed to add external asset'))
    }
  }

  const handleEdit = async () => {
    if (!editAsset || !formData.name) {
      toast.error('Please enter an asset name')
      return
    }
    // Persist through the real API. This previously only mutated local state and
    // reported success, so edits silently reverted on the next refetch.
    try {
      await updateAsset(editAsset.id, {
        name: formData.name,
        description: formData.notes || undefined,
        metadata: {
          ...(formData.ipAddress ? { ip_address: formData.ipAddress } : {}),
          ...(formData.port ? { port: Number(formData.port) } : {}),
          ...(formData.parentDomain ? { parent_domain: formData.parentDomain } : {}),
        },
      })
      toast.success('External asset updated successfully')
      setEditAsset(null)
      resetForm()
      await refetchAssets()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Failed to update external asset'))
    }
  }

  const handleDelete = async () => {
    if (!deleteAsset) return
    try {
      await apiDeleteAsset(deleteAsset.id)
      toast.success('External asset deleted successfully')
      setDeleteAsset(null)
      await refetchAssets()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Failed to delete external asset'))
    }
  }

  // Derive a scan target from an external asset: prefer resolved IP, fall back
  // to the asset name (domain / subdomain / service host is itself a target).
  const toScanCandidate = (a: ExternalAsset): ScanCandidate => ({
    id: a.id,
    label: a.name || a.ipAddress || a.id,
    target: (a.ipAddress || a.name || '').trim(),
  })

  const openScanDialog = (items: ExternalAsset[]) => {
    setScanCandidates(items.map(toScanCandidate))
    setScanDialogOpen(true)
  }

  const handleExport = () => {
    exportToCsv(
      filteredAssets,
      [
        { header: 'Name', accessor: (a) => a.name },
        { header: 'Type', accessor: (a) => a.type },
        { header: 'Parent Domain', accessor: (a) => a.parentDomain ?? '' },
        { header: 'IP Address', accessor: (a) => a.ipAddress ?? '' },
        { header: 'Port', accessor: (a) => a.port ?? '' },
        { header: 'Status', accessor: (a) => a.status },
        { header: 'Risk Level', accessor: (a) => a.riskLevel },
        { header: 'Findings', accessor: (a) => a.findingsCount },
        { header: 'Last Seen', accessor: (a) => a.lastSeen },
      ],
      'external-assets'
    )
  }

  const openEdit = (asset: ExternalAsset) => {
    setFormData({
      name: asset.name,
      type: asset.type,
      parentDomain: asset.parentDomain || '',
      ipAddress: asset.ipAddress || '',
      port: asset.port?.toString() || '',
      status: asset.status,
      riskLevel: asset.riskLevel,
      notes: asset.notes || '',
    })
    setEditAsset(asset)
  }

  const formFields = (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Asset Name *</Label>
          <Input
            placeholder="e.g., api.example.com"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          />
        </div>
        <div className="space-y-2">
          <Label>Type</Label>
          <Select
            value={formData.type}
            onValueChange={(v) => setFormData({ ...formData, type: v as AssetType })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="domain">Domain</SelectItem>
              <SelectItem value="subdomain">Subdomain</SelectItem>
              <SelectItem value="service">Service</SelectItem>
              <SelectItem value="certificate">Certificate</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label>Parent Domain</Label>
          <Input
            placeholder="e.g., example.com"
            value={formData.parentDomain}
            onChange={(e) => setFormData({ ...formData, parentDomain: e.target.value })}
          />
        </div>
        <div className="space-y-2">
          <Label>IP Address</Label>
          <Input
            placeholder="e.g., 192.168.1.1"
            value={formData.ipAddress}
            onChange={(e) => setFormData({ ...formData, ipAddress: e.target.value })}
          />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          <Label>Port</Label>
          <Input
            type="number"
            placeholder="e.g., 443"
            value={formData.port}
            onChange={(e) => setFormData({ ...formData, port: e.target.value })}
          />
        </div>
        <div className="space-y-2">
          <Label>Status</Label>
          <Select
            value={formData.status}
            onValueChange={(v) => setFormData({ ...formData, status: v as AssetStatus })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="inactive">Inactive</SelectItem>
              <SelectItem value="monitoring">Monitoring</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label>Risk Level</Label>
          <Select
            value={formData.riskLevel}
            onValueChange={(v) => setFormData({ ...formData, riskLevel: v as RiskLevel })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="space-y-2">
        <Label>Notes</Label>
        <Input
          placeholder="Additional notes..."
          value={formData.notes}
          onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
        />
      </div>
    </div>
  )

  return (
    <>
      <Main>
        <PageHeader
          title="External Attack Surface"
          description="Monitor and manage internet-facing assets and their exposure"
        >
          <div className="flex gap-2">
            <Can permission={Permission.ScansExecute}>
              <Button
                variant="outline"
                size="sm"
                onClick={() => openScanDialog(filteredAssets)}
                disabled={filteredAssets.length === 0}
              >
                <RefreshCw className="me-2 h-4 w-4" />
                Scan Now
              </Button>
            </Can>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="me-2 h-4 w-4" />
              Export
            </Button>
            <Can permission={Permission.ScopeWrite}>
              <Button size="sm" onClick={() => setIsCreateOpen(true)}>
                <Plus className="me-2 h-4 w-4" />
                Add Asset
              </Button>
            </Can>
          </div>
        </PageHeader>

        {/* Stats Cards */}
        <div className="grid gap-4 md:grid-cols-5 mb-6">
          <StatsCard
            title="Total Assets"
            value={stats.total}
            icon={Globe}
            description={`${stats.active} active`}
          />
          <StatsCard
            title="Critical Risk"
            value={stats.critical}
            valueClassName="text-red-600"
            icon={AlertTriangle}
            description="Needs immediate attention"
          />
          <StatsCard
            title="Total Findings"
            value={stats.totalFindings}
            icon={Shield}
            description="Across all assets"
          />
          <StatsCard
            title="Expiring Certs"
            value={stats.expiringCerts}
            valueClassName="text-amber-600"
            icon={Clock}
            description="Within 30 days"
          />
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Coverage</CardTitle>
              <CheckCircle2 className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-500">94%</div>
              <Progress value={94} className="mt-2" />
            </CardContent>
          </Card>
        </div>

        {/* Filters */}
        <Card className="mb-6">
          <CardContent className="pt-6">
            <div className="flex flex-wrap gap-4">
              <div className="flex-1 min-w-[200px]">
                <div className="relative">
                  <SearchIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search assets..."
                    className="ps-9"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Select
                  value={filterType}
                  onValueChange={(v) => setFilterType(v as AssetType | 'all')}
                >
                  <SelectTrigger className="w-32" aria-label="Filter by type">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="domain">Domain</SelectItem>
                    <SelectItem value="subdomain">Subdomain</SelectItem>
                    <SelectItem value="service">Service</SelectItem>
                    <SelectItem value="certificate">Certificate</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={filterRisk}
                  onValueChange={(v) => setFilterRisk(v as RiskLevel | 'all')}
                >
                  <SelectTrigger className="w-32" aria-label="Filter by risk">
                    <SelectValue placeholder="Risk" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Risks</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
                {(filterType !== 'all' || filterRisk !== 'all' || searchQuery) && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setFilterType('all')
                      setFilterRisk('all')
                      setSearchQuery('')
                    }}
                  >
                    <X className="me-1 h-3 w-3" />
                    Clear
                  </Button>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Assets Table */}
        <Card>
          <CardHeader>
            <CardTitle>External Assets</CardTitle>
            <CardDescription>
              {filteredAssets.length} of {assets.length} assets
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>IP / Port</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead className="w-[50px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAssets.map((asset) => {
                  const TypeIcon = typeIcons[asset.type] ?? Globe
                  return (
                    <TableRow
                      key={asset.id}
                      className="cursor-pointer"
                      onClick={() => setViewAsset(asset)}
                    >
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                            <TypeIcon className="h-4 w-4 text-primary" />
                          </div>
                          <div>
                            <p className="font-medium">{asset.name}</p>
                            {asset.parentDomain && (
                              <p className="text-xs text-muted-foreground">{asset.parentDomain}</p>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {asset.type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs">
                          {asset.ipAddress}
                          {asset.port && `:${asset.port}`}
                        </code>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={statusColors[asset.status]}>
                          {asset.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={riskColors[asset.riskLevel]}>
                          {asset.riskLevel}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span
                          className={asset.findingsCount > 0 ? 'text-orange-500 font-medium' : ''}
                        >
                          {asset.findingsCount}
                        </span>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {new Date(asset.lastSeen).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <Can permission={[Permission.ScopeWrite, Permission.ScopeDelete]}>
                          <span onClick={(e) => e.stopPropagation()}>
                            <DataTableRowActions
                              actions={[
                                {
                                  label: 'View Details',
                                  icon: Eye,
                                  onClick: () => setViewAsset(asset),
                                },
                                {
                                  label: 'Edit',
                                  icon: Pencil,
                                  onClick: () => openEdit(asset),
                                  permission: Permission.ScopeWrite,
                                },
                                {
                                  label: 'Delete',
                                  icon: Trash2,
                                  onClick: () => setDeleteAsset(asset),
                                  destructive: true,
                                  permission: Permission.ScopeDelete,
                                },
                              ]}
                            />
                          </span>
                        </Can>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </Main>

      {/* Create Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add External Asset</DialogTitle>
            <DialogDescription>Add a new internet-facing asset to monitor</DialogDescription>
          </DialogHeader>
          {formFields}
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate}>Add Asset</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editAsset} onOpenChange={(open) => !open && setEditAsset(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit External Asset</DialogTitle>
            <DialogDescription>Update asset information</DialogDescription>
          </DialogHeader>
          {formFields}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditAsset(null)}>
              Cancel
            </Button>
            <Button onClick={handleEdit}>Save Changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog open={!!deleteAsset} onOpenChange={(open) => !open && setDeleteAsset(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Asset</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{deleteAsset?.name}&quot;? This action cannot be
              undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteAsset(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDelete}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* View Sheet */}
      {viewAsset && (
        <DetailSheet
          open
          onOpenChange={(open) => !open && setViewAsset(null)}
          header={
            <DetailHeader
              title={viewAsset.name}
              badges={
                <>
                  <Badge variant="outline" className={statusColors[viewAsset.status]}>
                    {viewAsset.status}
                  </Badge>
                  <Badge variant="outline" className={riskColors[viewAsset.riskLevel]}>
                    {viewAsset.riskLevel} risk
                  </Badge>
                </>
              }
              meta={[viewAsset.type]}
              actions={
                <>
                  <Button
                    size="sm"
                    onClick={() => router.push(`/findings?assetId=${viewAsset.id}`)}
                  >
                    <ExternalLink className="h-4 w-4" />
                    View findings
                  </Button>
                  {canWriteScope && (
                    <Button size="sm" variant="outline" onClick={() => openEdit(viewAsset)}>
                      <Pencil className="h-4 w-4" />
                      Edit
                    </Button>
                  )}
                </>
              }
              onClose={() => setViewAsset(null)}
            />
          }
        >
          <div className="space-y-5">
            <DetailStatGrid aria-label="Key numbers">
              <DetailStat
                label="Findings"
                value={viewAsset.findingsCount}
                tone={viewAsset.findingsCount > 0 ? 'warning' : 'default'}
              />
              <DetailStat
                label="SSL expiry"
                value={
                  viewAsset.sslExpiry
                    ? new Date(viewAsset.sslExpiry).toLocaleDateString()
                    : 'No SSL'
                }
              />
            </DetailStatGrid>

            <DetailSections>
              {viewAsset.ipAddress && (
                <DetailSection title="Network">
                  <p className="font-mono text-sm break-all">
                    {viewAsset.ipAddress}
                    {viewAsset.port && `:${viewAsset.port}`}
                  </p>
                </DetailSection>
              )}

              {viewAsset.technologies && viewAsset.technologies.length > 0 && (
                <DetailSection title="Technologies" count={viewAsset.technologies.length}>
                  <div className="flex flex-wrap gap-1.5">
                    {viewAsset.technologies.map((tech) => (
                      <Badge key={tech} variant="secondary">
                        {tech}
                      </Badge>
                    ))}
                  </div>
                </DetailSection>
              )}

              {viewAsset.notes && (
                <DetailSection title="Notes">
                  <p className="text-sm text-muted-foreground">{viewAsset.notes}</p>
                </DetailSection>
              )}

              <DetailSection title="Timeline">
                <DetailFieldGrid>
                  <DetailField label="Discovered">
                    {new Date(viewAsset.discoveredAt).toLocaleDateString()}
                  </DetailField>
                  <DetailField label="Last seen">
                    {new Date(viewAsset.lastSeen).toLocaleDateString()}
                  </DetailField>
                </DetailFieldGrid>
              </DetailSection>
            </DetailSections>
          </div>
        </DetailSheet>
      )}

      {/* Quick-scan flow */}
      <ScanAssetsDialog
        open={scanDialogOpen}
        onOpenChange={setScanDialogOpen}
        candidates={scanCandidates}
        title="Scan external assets"
      />
    </>
  )
}
