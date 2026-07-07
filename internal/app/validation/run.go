package validation

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// FindingLookup is the narrow read seam over the finding repository.
type FindingLookup interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// AssetLookup is the narrow read seam over the asset repository.
type AssetLookup interface {
	GetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)
}

// defaultTimeoutSeconds bounds how long an agent may spend on a single
// validation job before the platform reclaims it.
const defaultTimeoutSeconds = 120

// safeCheckTechnique is the ATT&CK technique used for the non-intrusive
// reachability re-check. It is one of the techniques DefaultSelector's
// safe-check kind is allowed to run (see kindSupportsTechnique).
const safeCheckTechnique TechniqueID = "T1046"

// ErrNotNetworkAddressable is returned when a finding's asset has no network
// address a safe-check reachability probe can dial (e.g. a code repository,
// container image, or cloud-account finding). Callers that auto-dispatch
// validation (e.g. proof-of-fix on fix_applied) treat it as an expected skip,
// not a failure.
var ErrNotNetworkAddressable = fmt.Errorf("%w: asset is not network-addressable for a safe-check re-check", shared.ErrValidation)

// networkAddressableTypes is the set of asset types whose Name() is a host,
// IP, or URL a safe-check probe can reach over the network. Types outside this
// set (repository, container, cloud_account, …) cannot be reachability-probed.
var networkAddressableTypes = map[asset.AssetType]bool{
	asset.AssetTypeDomain:         true,
	asset.AssetTypeSubdomain:      true,
	asset.AssetTypeIPAddress:      true,
	asset.AssetTypeWebsite:        true,
	asset.AssetTypeWebApplication: true,
	asset.AssetTypeAPI:            true,
	asset.AssetTypeService:        true,
	asset.AssetTypeHost:           true,
}

// isNetworkAddressable reports whether a safe-check reachability probe can
// meaningfully target an asset of the given type.
func isNetworkAddressable(t asset.AssetType) bool {
	return networkAddressableTypes[t]
}

// RunService turns "validate this finding" into a dispatched validation job.
// It resolves the finding's asset into a Target, picks an executor kind via the
// Selector against the fleet's available kinds, and hands the job to the
// dispatcher. Evidence returns asynchronously through EvidenceIngestService.
type RunService struct {
	findings   FindingLookup
	assets     AssetLookup
	dispatcher JobDispatcher
	selector   Selector
	available  []ExecutorKind
	logger     *logger.Logger
}

// NewRunService wires the run service. available is the set of executor kinds
// the agent fleet supports; the MVP passes {KindSafeCheck}.
func NewRunService(
	findings FindingLookup,
	assets AssetLookup,
	dispatcher JobDispatcher,
	selector Selector,
	available []ExecutorKind,
	log *logger.Logger,
) *RunService {
	return &RunService{
		findings:   findings,
		assets:     assets,
		dispatcher: dispatcher,
		selector:   selector,
		available:  available,
		logger:     log.With("service", "validation-run"),
	}
}

// ValidateFinding dispatches a validation job for the given finding and returns
// the command ID it was queued under.
func (s *RunService) ValidateFinding(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error) {
	if tenantID.IsZero() || findingID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: tenant and finding ids are required", shared.ErrValidation)
	}

	f, err := s.findings.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("finding lookup: %w", err)
	}

	assetID := f.AssetID()
	if assetID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: finding has no asset to validate against", shared.ErrValidation)
	}

	a, err := s.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("asset lookup: %w", err)
	}

	if !isNetworkAddressable(a.Type()) {
		return shared.ID{}, ErrNotNetworkAddressable
	}

	address := strings.TrimSpace(a.Name())
	if address == "" {
		return shared.ID{}, fmt.Errorf("%w: asset has no address to validate against", shared.ErrValidation)
	}

	technique := safeCheckTechnique
	kind, err := s.selector.Select(technique, nil, s.available)
	if err != nil {
		return shared.ID{}, fmt.Errorf("no validation executor available for finding: %w", err)
	}

	job := ValidationJob{
		JobID:        shared.NewID(),
		TenantID:     tenantID,
		FindingID:    findingID,
		ExecutorKind: kind,
		Technique:    technique,
		Target: Target{
			AssetID: assetID,
			Type:    a.Type().String(),
			Address: address,
		},
		TimeoutSeconds: defaultTimeoutSeconds,
	}

	cmdID, err := s.dispatcher.Dispatch(ctx, job)
	if err != nil {
		return shared.ID{}, err
	}

	s.logger.Info("finding validation requested",
		"tenant_id", tenantID.String(),
		"finding_id", findingID.String(),
		"asset_id", assetID.String(),
		"executor_kind", string(kind),
		"command_id", cmdID.String(),
	)
	return cmdID, nil
}
