package cirun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakePromoter struct{ promoted []shared.ID }

func (p *fakePromoter) PromoteSecretFindings(_ context.Context, _, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	p.promoted = append(p.promoted, ids...)
	return ids, nil
}

type fakeRotationTasks struct {
	byKey   map[string]*remediation.Task
	created []*remediation.NewTaskRecord
	joined  map[shared.ID][]shared.ID
	// raceWinner, when set, is a task another run opens between our lookup
	// and our insert: CreateTask refuses with ErrActiveTaskExists.
	raceWinner *remediation.Task
}

func newFakeRotationTasks() *fakeRotationTasks {
	return &fakeRotationTasks{byKey: map[string]*remediation.Task{}, joined: map[shared.ID][]shared.ID{}}
}

func (t *fakeRotationTasks) ActiveTaskByActionKey(_ context.Context, _ shared.ID, key string) (*remediation.Task, error) {
	return t.byKey[key], nil
}

func (t *fakeRotationTasks) CreateTask(_ context.Context, rec *remediation.NewTaskRecord) error {
	if t.raceWinner != nil {
		w := t.raceWinner
		t.raceWinner = nil
		t.byKey[rec.Action.Key] = w
		return remediation.ErrActiveTaskExists
	}
	t.created = append(t.created, rec)
	task := rec.Task
	task.Version = 1
	t.byKey[rec.Action.Key] = &task
	return nil
}

func (t *fakeRotationTasks) AddMembers(_ context.Context, _, taskID shared.ID, _ int, ids []shared.ID, _ remediation.MemberRole, _ remediation.JoinSource, _ *shared.ID) (*remediation.Task, error) {
	t.joined[taskID] = append(t.joined[taskID], ids...)
	return nil, nil
}

func secretFinding(rule, fp string, valid *bool) cirun.RunFinding {
	return cirun.RunFinding{ID: shared.NewID(), Fingerprint: "f-" + fp, FindingType: "secret", Status: "new",
		RuleID: rule, SecretType: "aws_access_key", SecretFingerprint: fp, SecretValid: valid}
}

const hexFP = "0123456789abcdef0123456789abcdef"

func TestSecretExposure_PromotesAndOpensOneRotationTaskPerSecretIdentity(t *testing.T) {
	pr, tasks := &fakePromoter{}, newFakeRotationTasks()
	x := NewSecretExposure(pr, tasks, logger.NewNop())
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), RepositoryAssetID: shared.NewID()}

	a := secretFinding("aws-access-token", hexFP, nil)
	out := x.Raise(context.Background(), run, []cirun.RunFinding{a})
	if len(out) != 1 || !out[0].Created || out[0].Title != "Rotate aws_access_key" {
		t.Fatalf("first raise = %+v", out)
	}
	if len(pr.promoted) != 1 || pr.promoted[0] != a.ID {
		t.Fatalf("the finding was not made an organization finding: %v", pr.promoted)
	}
	rec := tasks.created[0]
	if rec.Action.Key != "rotate:secret:"+hexFP || rec.Action.Kind != remediation.KindRotate || rec.Action.Origin != remediation.ActionOriginSystem {
		t.Fatalf("action = %+v", rec.Action)
	}
	if rec.Task.CreatedBy != nil || rec.ActorID != nil {
		t.Fatal("a system task names no person")
	}

	// The same credential in another repository joins the task, no second one.
	b := secretFinding("aws-access-token", hexFP, nil)
	out = x.Raise(context.Background(), run, []cirun.RunFinding{b})
	if len(tasks.created) != 1 || len(out) != 1 || out[0].Created || len(tasks.joined[out[0].TaskID]) != 1 {
		t.Fatalf("same identity: created=%d out=%+v joined=%v", len(tasks.created), out, tasks.joined)
	}

	// Another credential opens its own task.
	c := secretFinding("aws-access-token", "ffffffffffffffffffffffffffffffff", nil)
	x.Raise(context.Background(), run, []cirun.RunFinding{c})
	if len(tasks.created) != 2 {
		t.Fatalf("a different secret must open its own task: %d", len(tasks.created))
	}
}

func TestSecretExposure_DoesNotPageForDeadGenericForkSuppressedOrClosed(t *testing.T) {
	no := false
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), RepositoryAssetID: shared.NewID()}
	suppressed := secretFinding("aws-access-token", hexFP, nil)
	suppressed.Suppressed = true
	closed := secretFinding("aws-access-token", hexFP, nil)
	closed.Status = "resolved"
	notSecret := secretFinding("aws-access-token", hexFP, nil)
	notSecret.FindingType = "vulnerability"
	for name, f := range map[string]cirun.RunFinding{
		"validated false": secretFinding("aws-access-token", hexFP, &no),
		"generic rule":    secretFinding("generic-api-key", hexFP, nil),
		"password rule":   secretFinding("hardcoded-password", hexFP, nil),
		"suppressed":      suppressed, "closed": closed, "not a secret": notSecret,
	} {
		pr, tasks := &fakePromoter{}, newFakeRotationTasks()
		out := NewSecretExposure(pr, tasks, logger.NewNop()).Raise(context.Background(), run, []cirun.RunFinding{f})
		if len(out) != 0 || len(pr.promoted) != 0 || len(tasks.created) != 0 {
			t.Errorf("%s paged: out=%v promoted=%v created=%d", name, out, pr.promoted, len(tasks.created))
		}
	}
	// A fork records nothing as exposure.
	fork := *run
	fork.Fork = true
	pr, tasks := &fakePromoter{}, newFakeRotationTasks()
	if out := NewSecretExposure(pr, tasks, logger.NewNop()).Raise(context.Background(), &fork,
		[]cirun.RunFinding{secretFinding("aws-access-token", hexFP, nil)}); len(out) != 0 || len(tasks.created) != 0 || len(pr.promoted) != 0 {
		t.Fatal("a fork run raised a secret")
	}
}

func TestRotationTitleIsCleanedAndCapped(t *testing.T) {
	if got := RotationTitle(""); got != "Rotate secret" {
		t.Fatalf("empty type = %q", got)
	}
	got := RotationTitle("aws\nkey\x00 " + strings.Repeat("x", 500))
	if strings.ContainsAny(got, "\n\x00") || len(got) > len("Rotate ")+60 {
		t.Fatalf("title not cleaned: %q", got)
	}
}

// Two runs find the same secret at once: the loser's insert is refused by the
// one-active-task-per-action index and it joins the winner's task.
func TestSecretExposure_LosingTheCreateRaceJoinsTheExistingTask(t *testing.T) {
	pr, tasks := &fakePromoter{}, newFakeRotationTasks()
	winner := &remediation.Task{ID: shared.NewID(), Title: "Rotate aws_access_key", Version: 1}
	tasks.raceWinner = winner
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), RepositoryAssetID: shared.NewID()}
	f := secretFinding("aws-access-token", hexFP, nil)
	out := NewSecretExposure(pr, tasks, logger.NewNop()).Raise(context.Background(), run, []cirun.RunFinding{f})
	if len(out) != 1 || out[0].Created || out[0].TaskID != winner.ID || len(tasks.joined[winner.ID]) != 1 {
		t.Fatalf("loser did not join the winner: out=%+v joined=%v", out, tasks.joined)
	}
}
