package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AssetImportService handles bulk asset import from various formats.
type AssetImportService struct {
	assetRepo asset.Repository
	logger    *logger.Logger
}

// NewAssetImportService creates a new AssetImportService.
func NewAssetImportService(assetRepo asset.Repository, log *logger.Logger) *AssetImportService {
	return &AssetImportService{
		assetRepo: assetRepo,
		logger:    log.With("service", "asset-import"),
	}
}

// AssetImportResult contains the result of an import operation.
type AssetImportResult struct {
	AssetsCreated int      `json:"assets_created"`
	AssetsUpdated int      `json:"assets_updated"`
	AssetsSkipped int      `json:"assets_skipped"`
	Errors        []string `json:"errors,omitempty"`
}

// ImportCSVAssets imports assets from CSV data.
// Expected columns: name, type, sub_type, description, tags, properties (JSON)
func (s *AssetImportService) ImportCSVAssets(ctx context.Context, tenantID string, reader io.Reader) (*AssetImportResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	csvReader := csv.NewReader(reader)
	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read CSV header", shared.ErrValidation)
	}

	colIndex := make(map[string]int, len(header))
	for i, col := range header {
		colIndex[strings.ToLower(strings.TrimSpace(col))] = i
	}

	nameIdx, hasName := colIndex["name"]
	typeIdx, hasType := colIndex["type"]
	if !hasName || !hasType {
		return nil, fmt.Errorf("%w: CSV must have 'name' and 'type' columns", shared.ErrValidation)
	}

	result := &AssetImportResult{}
	for {
		record, readErr := csvReader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("row read error: %v", readErr))
			continue
		}

		name := strings.TrimSpace(record[nameIdx])
		assetType := strings.TrimSpace(record[typeIdx])
		if name == "" || assetType == "" {
			result.AssetsSkipped++
			continue
		}

		a, createErr := asset.NewAssetWithTenant(tid, name, asset.AssetType(assetType), asset.CriticalityMedium)
		if createErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid asset %s: %v", name, createErr))
			continue
		}

		if idx, ok := colIndex["sub_type"]; ok && idx < len(record) {
			a.SetSubType(strings.TrimSpace(record[idx]))
		}
		if idx, ok := colIndex["description"]; ok && idx < len(record) {
			a.UpdateDescription(strings.TrimSpace(record[idx]))
		}
		if idx, ok := colIndex["tags"]; ok && idx < len(record) {
			for _, t := range strings.Split(record[idx], ";") {
				if t = strings.TrimSpace(t); t != "" {
					a.AddTag(t)
				}
			}
		}
		if idx, ok := colIndex["properties"]; ok && idx < len(record) {
			var props map[string]any
			if json.Unmarshal([]byte(record[idx]), &props) == nil {
				a.SetProperties(props)
			}
		}

		if createErr := s.assetRepo.Create(ctx, a); createErr != nil {
			if strings.Contains(createErr.Error(), "already exists") {
				result.AssetsSkipped++
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("create %s: %v", name, createErr))
			}
			continue
		}
		result.AssetsCreated++
	}

	s.logger.Info("CSV asset import completed",
		"tenant_id", tenantID,
		"created", result.AssetsCreated,
		"skipped", result.AssetsSkipped,
	)
	return result, nil
}

// =============================================================================
// Nessus XML Import
// =============================================================================

type nessusReport struct {
	XMLName xml.Name       `xml:"NessusClientData_v2"`
	Reports []nessusTarget `xml:"Report>ReportHost"`
}

type nessusTarget struct {
	Name       string             `xml:"name,attr"`
	Properties []nessusHostProp   `xml:"HostProperties>tag"`
	Items      []nessusReportItem `xml:"ReportItem"`
}

type nessusHostProp struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusReportItem struct {
	Port       int    `xml:"port,attr"`
	Protocol   string `xml:"protocol,attr"`
	PluginName string `xml:"pluginName,attr"`
	Severity   int    `xml:"severity,attr"`
}

// ImportNessus imports hosts from Nessus XML export.
func (s *AssetImportService) ImportNessus(ctx context.Context, tenantID string, reader io.Reader) (*AssetImportResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	data, err := io.ReadAll(io.LimitReader(reader, 100*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read nessus data: %w", err)
	}

	var report nessusReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("%w: invalid Nessus XML format", shared.ErrValidation)
	}

	result := &AssetImportResult{}

	for _, host := range report.Reports {
		hostname := host.Name
		props := make(map[string]any)
		var os string

		for _, p := range host.Properties {
			switch p.Name {
			case "host-ip":
				props["ip_address"] = p.Value
				if hostname == "" {
					hostname = p.Value
				}
			case "operating-system":
				os = p.Value
				props["os"] = p.Value
			case "host-fqdn":
				if p.Value != "" {
					hostname = p.Value
				}
				props["fqdn"] = p.Value
			case "mac-address":
				props["mac_address"] = p.Value
			}
		}

		if hostname == "" {
			result.AssetsSkipped++
			continue
		}

		a, createErr := asset.NewAssetWithTenant(tid, hostname, asset.AssetTypeHost, asset.CriticalityMedium)
		if createErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid host %s: %v", hostname, createErr))
			continue
		}

		if os != "" {
			a.SetSubType(normalizeOS(os))
		}
		a.SetProperties(props)
		a.SetDiscoverySource("nessus")
		now := time.Now().UTC()
		a.SetDiscoveredAt(&now)

		openPorts := 0
		for _, item := range host.Items {
			if item.Port > 0 {
				openPorts++
			}
		}
		a.UpdateDescription(fmt.Sprintf("Discovered by Nessus (%d services)", openPorts))

		if createErr := s.assetRepo.Create(ctx, a); createErr != nil {
			if strings.Contains(createErr.Error(), "already exists") {
				result.AssetsUpdated++
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("host %s: %v", hostname, createErr))
			}
			continue
		}
		result.AssetsCreated++
	}

	s.logger.Info("Nessus import completed", "tenant_id", tenantID, "created", result.AssetsCreated)
	return result, nil
}

func normalizeOS(os string) string {
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "linux"):
		return "linux"
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "macos"), strings.Contains(lower, "mac os"):
		return "macos"
	default:
		return "other"
	}
}

// =============================================================================
// Kubernetes Discovery
// =============================================================================

// K8sDiscoveryInput holds Kubernetes cluster info for asset import.
type K8sDiscoveryInput struct {
	ClusterName string         `json:"cluster_name"`
	Namespaces  []K8sNamespace `json:"namespaces"`
}

// K8sNamespace holds namespace + workloads.
type K8sNamespace struct {
	Name      string        `json:"name"`
	Workloads []K8sWorkload `json:"workloads"`
}

// K8sWorkload represents a Kubernetes workload.
type K8sWorkload struct {
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Replicas  int               `json:"replicas"`
	Images    []string          `json:"images"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ImportKubernetes imports assets from a Kubernetes cluster discovery report.
func (s *AssetImportService) ImportKubernetes(ctx context.Context, tenantID string, input K8sDiscoveryInput) (*AssetImportResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	if input.ClusterName == "" {
		return nil, fmt.Errorf("%w: cluster_name is required", shared.ErrValidation)
	}

	result := &AssetImportResult{}
	now := time.Now().UTC()

	// Create cluster asset
	cluster, clusterErr := asset.NewAssetWithTenant(tid, input.ClusterName, asset.AssetType("host"), asset.CriticalityHigh)
	if clusterErr == nil {
		cluster.SetSubType("kubernetes_cluster")
		cluster.SetProperties(map[string]any{"namespace_count": len(input.Namespaces)})
		cluster.SetDiscoverySource("kubernetes")
		cluster.SetDiscoveredAt(&now)

		if err := s.assetRepo.Create(ctx, cluster); err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				result.Errors = append(result.Errors, fmt.Sprintf("cluster: %v", err))
			}
		} else {
			result.AssetsCreated++
		}
	}

	// Create workload assets
	for _, ns := range input.Namespaces {
		for _, wl := range ns.Workloads {
			name := fmt.Sprintf("%s/%s", ns.Name, wl.Name)

			a, createErr := asset.NewAssetWithTenant(tid, name, asset.AssetType("container"), asset.CriticalityMedium)
			if createErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("workload %s: %v", name, createErr))
				continue
			}

			a.SetSubType(strings.ToLower(wl.Kind))
			a.UpdateDescription(fmt.Sprintf("%s in %s (%d replicas)", wl.Kind, ns.Name, wl.Replicas))
			a.SetDiscoverySource("kubernetes")
			a.SetDiscoveredAt(&now)

			props := map[string]any{
				"namespace":    ns.Name,
				"kind":         wl.Kind,
				"replicas":     wl.Replicas,
				"cluster_name": input.ClusterName,
			}
			if len(wl.Images) > 0 {
				props["images"] = wl.Images
			}
			a.SetProperties(props)
			a.AddTag("kubernetes")
			a.AddTag(ns.Name)

			if err := s.assetRepo.Create(ctx, a); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					result.AssetsUpdated++
				} else {
					result.Errors = append(result.Errors, fmt.Sprintf("workload %s: %v", name, err))
				}
				continue
			}
			result.AssetsCreated++
		}
	}

	s.logger.Info("Kubernetes import completed",
		"tenant_id", tenantID, "cluster", input.ClusterName, "created", result.AssetsCreated,
	)
	return result, nil
}
