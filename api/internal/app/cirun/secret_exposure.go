package cirun

// A secret a CI run finds on any non-fork branch is exposure the moment it
// is pushed (research 150 section 3A.3 item 6): it becomes an organization
// finding at once instead of staying hidden as seen only on a branch, and
// has a remediation task "Rotate <secret type>". Removing it from the branch
// does not close it, because history keeps it.
//
// Which secrets (cirun.RunFinding.SecretPages): not validated false, and not
// matched by a generic or heuristic rule. A hard-coded password hit does not
// page. A fork never gets here (its run records nothing as exposure).
//
// One task per secret identity: the task's action key is
// "rotate:secret:<fingerprint>" (the remediation group key of the secret), so
// the same credential found in several repositories or branches joins one
// task, and a second sighting never opens a second task.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxSecretsPerUpload bounds how many secret findings one upload raises.
const maxSecretsPerUpload = 200

// SecretPromoter makes secret findings organization findings.
type SecretPromoter interface {
	PromoteSecretFindings(ctx context.Context, tenantID, assetID shared.ID, ids []shared.ID) ([]shared.ID, error)
}

// RotationTaskStore is the slice of the remediation task repository the
// rotation tasks need.
type RotationTaskStore interface {
	ActiveTaskByActionKey(ctx context.Context, tenantID shared.ID, actionKey string) (*remediation.Task, error)
	CreateTask(ctx context.Context, rec *remediation.NewTaskRecord) error
	AddMembers(ctx context.Context, tenantID, taskID shared.ID, expectedVersion int, ids []shared.ID, role remediation.MemberRole, src remediation.JoinSource, actor *shared.ID) (*remediation.Task, error)
}

// SecretRotation is one rotation task a run opened or joined.
type SecretRotation struct {
	FindingID shared.ID
	TaskID    shared.ID
	Title     string
	Created   bool
}

// SecretExposure raises paging secrets as organization findings with a
// rotation task.
type SecretExposure struct {
	promoter SecretPromoter
	tasks    RotationTaskStore
	log      *logger.Logger
}

// NewSecretExposure creates it.
func NewSecretExposure(p SecretPromoter, t RotationTaskStore, log *logger.Logger) *SecretExposure {
	if log == nil {
		log = logger.NewNop()
	}
	return &SecretExposure{promoter: p, tasks: t, log: log}
}

// RotationTitle is the title of the rotation task of a secret of this type.
// The type comes from the scanner's report, so it is cleaned and capped.
func RotationTitle(secretType string) string {
	t := cirun.SanitizeLabel(secretType, 60)
	if strings.TrimSpace(t) == "" {
		return "Rotate secret"
	}
	return "Rotate " + t
}

// Raise promotes the paging secret findings of the run's repository and opens
// or joins their rotation tasks. A failure on one finding is logged and does
// not stop the others (the upload already succeeded).
func (e *SecretExposure) Raise(ctx context.Context, run *cirun.Run, findings []cirun.RunFinding) []SecretRotation {
	if run == nil || run.Fork {
		return nil
	}
	paging := make([]cirun.RunFinding, 0, min(len(findings), maxSecretsPerUpload))
	for _, f := range findings {
		if !f.SecretPages() || f.Suppressed || !vulnerability.IsOpenStatus(vulnerability.FindingStatus(f.Status)) {
			continue
		}
		paging = append(paging, f)
		if len(paging) >= maxSecretsPerUpload {
			break
		}
	}
	if len(paging) == 0 {
		return nil
	}
	ids := make([]shared.ID, 0, len(paging))
	for _, f := range paging {
		ids = append(ids, f.ID)
	}
	if _, err := e.promoter.PromoteSecretFindings(ctx, run.TenantID, run.RepositoryAssetID, ids); err != nil {
		e.log.Warn("ci secret not promoted to an organization finding", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
	}
	var out []SecretRotation
	for _, f := range paging {
		r, err := e.ensureTask(ctx, run.TenantID, f)
		if err != nil {
			e.log.Warn("ci secret rotation task not opened", "run_id", run.ID.String(), "finding_id", f.ID.String(), "error", logger.SanitizeError(err))
			continue
		}
		if r != nil {
			out = append(out, *r)
		}
	}
	return out
}

func (e *SecretExposure) ensureTask(ctx context.Context, tenantID shared.ID, f cirun.RunFinding) (*SecretRotation, error) {
	key, _, ok := remediation.DeriveKey(remediation.KeyInput{
		Source: "secret", FindingType: "secret", SecretFingerprint: f.SecretIdentity(), SecretType: f.SecretType,
	})
	if !ok {
		return nil, fmt.Errorf("secret has no usable identity")
	}
	title := RotationTitle(f.SecretType)
	existing, err := e.tasks.ActiveTaskByActionKey(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	return e.joinOrCreate(ctx, tenantID, f, key, title, existing, true)
}

// joinOrCreate joins the action's active task, or opens one. When another run
// opened it first (the create refuses a second active task for the action), it
// looks the task up again and joins it, once.
func (e *SecretExposure) joinOrCreate(ctx context.Context, tenantID shared.ID, f cirun.RunFinding, key, title string, existing *remediation.Task, retry bool) (*SecretRotation, error) {
	if existing != nil {
		if _, err := e.tasks.AddMembers(ctx, tenantID, existing.ID, existing.Version, []shared.ID{f.ID},
			remediation.MemberRolePrimary, remediation.JoinSourceAutoJoin, nil); err != nil {
			var other *remediation.FindingsInOtherTaskError
			if errors.As(err, &other) {
				return nil, nil // the finding already has its own task
			}
			return nil, err
		}
		return &SecretRotation{FindingID: f.ID, TaskID: existing.ID, Title: existing.Title}, nil
	}
	taskID := shared.NewID()
	rec := &remediation.NewTaskRecord{
		Task: remediation.Task{ID: taskID, TenantID: tenantID, Title: title,
			Description: "A CI run found this secret in the repository. Rotate it at its provider; removing it from the branch does not remove it from history."},
		Action: remediation.Action{TenantID: tenantID, Key: key, Kind: remediation.KindRotate, Title: title,
			FixSpec: remediation.FixSpecForKey(key), Origin: remediation.ActionOriginSystem},
		Members: []shared.ID{f.ID}, Source: remediation.JoinSourceAutoJoin, OneActive: true,
		EventData: map[string]any{"title": title, "reason": "ci_secret"},
	}
	if err := e.tasks.CreateTask(ctx, rec); err != nil {
		if errors.Is(err, remediation.ErrActiveTaskExists) && retry {
			winner, lerr := e.tasks.ActiveTaskByActionKey(ctx, tenantID, key)
			if lerr != nil {
				return nil, lerr
			}
			if winner == nil {
				return nil, err
			}
			return e.joinOrCreate(ctx, tenantID, f, key, title, winner, false)
		}
		var other *remediation.FindingsInOtherTaskError
		if errors.As(err, &other) {
			return nil, nil
		}
		return nil, err
	}
	return &SecretRotation{FindingID: f.ID, TaskID: taskID, Title: title, Created: true}, nil
}
