package validation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

type memEvidenceRepo struct {
	mu    sync.Mutex
	rows  []StoredEvidence
	err   error
}

func (m *memEvidenceRepo) Create(_ context.Context, ev StoredEvidence) error {
	if m.err != nil {
		return m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, ev)
	return nil
}

func (m *memEvidenceRepo) ListByFinding(_ context.Context, tenantID, findingID shared.ID) ([]StoredEvidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredEvidence
	for _, r := range m.rows {
		if r.TenantID == tenantID && r.FindingID == findingID {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestRedactor_AWSKeyID(t *testing.T) {
	r := NewRedactor()
	in := "found AKIAIOSFODNN7EXAMPLE in stdout"
	out := r.redactString(in)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("AWS key id not redacted: %q", out)
	}
}

func TestRedactor_Bearer(t *testing.T) {
	r := NewRedactor()
	in := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
	out := r.redactString(in)
	if strings.Contains(out, "eyJhbGciOiJ") {
		t.Fatalf("bearer not redacted: %q", out)
	}
}

func TestRedactor_PrivateKeyHeader(t *testing.T) {
	r := NewRedactor()
	in := "-----BEGIN RSA PRIVATE KEY-----\nAAAA..."
	out := r.redactString(in)
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("private key header not redacted: %q", out)
	}
}

func TestRedactor_Password(t *testing.T) {
	r := NewRedactor()
	in := "password=hunter2"
	out := r.redactString(in)
	if strings.Contains(out, "hunter2") {
		t.Fatalf("password not redacted: %q", out)
	}
}

func TestRedactor_RawMetaStrings(t *testing.T) {
	r := NewRedactor()
	ev := Evidence{
		RawMeta: map[string]any{
			"stdout":    "AKIAIOSFODNN7EXAMPLE leaked",
			"exit_code": 0,
		},
	}
	cleaned := r.Redact(ev)
	if strings.Contains(cleaned.RawMeta["stdout"].(string), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("stdout not redacted in RawMeta")
	}
	// Non-string values untouched.
	if cleaned.RawMeta["exit_code"] != 0 {
		t.Fatal("non-string value mutated")
	}
}

func TestRedactor_AddPattern(t *testing.T) {
	r := NewRedactor()
	r.AddPattern(`MYCORP-[0-9]+`)
	out := r.redactString("token MYCORP-12345 here")
	if strings.Contains(out, "MYCORP-12345") {
		t.Fatalf("custom pattern not applied: %q", out)
	}
}

func TestEvidenceStore_Record_PersistsRedacted(t *testing.T) {
	repo := &memEvidenceRepo{}
	s := NewEvidenceStore(repo)
	tid := shared.NewID()
	fid := shared.NewID()

	stored, err := s.Record(context.Background(), tid, fid, nil, Evidence{
		ExecutorKind: "atomic-red-team",
		Summary:      "found AKIAIOSFODNN7EXAMPLE",
		RawMeta:      map[string]any{"stdout": "password=hunter2"},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if stored.ID.IsZero() {
		t.Fatal("stored id not set")
	}
	if strings.Contains(stored.Evidence.Summary, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("summary not redacted")
	}
	if strings.Contains(stored.Evidence.RawMeta["stdout"].(string), "hunter2") {
		t.Fatalf("stdout not redacted")
	}
}

func TestEvidenceStore_Record_RequiresIDs(t *testing.T) {
	s := NewEvidenceStore(&memEvidenceRepo{})
	if _, err := s.Record(context.Background(), shared.ID{}, shared.NewID(), nil, Evidence{}); err == nil {
		t.Fatal("missing tenant must error")
	}
	if _, err := s.Record(context.Background(), shared.NewID(), shared.ID{}, nil, Evidence{}); err == nil {
		t.Fatal("missing finding must error")
	}
}

func TestEvidenceStore_Record_PropagatesRepoError(t *testing.T) {
	boom := errors.New("db down")
	s := NewEvidenceStore(&memEvidenceRepo{err: boom})
	_, err := s.Record(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestEvidenceStore_ListForFinding(t *testing.T) {
	repo := &memEvidenceRepo{}
	s := NewEvidenceStore(repo)
	tid := shared.NewID()
	fid := shared.NewID()
	otherFid := shared.NewID()

	_, _ = s.Record(context.Background(), tid, fid, nil, Evidence{Summary: "a"})
	_, _ = s.Record(context.Background(), tid, otherFid, nil, Evidence{Summary: "b"})
	_, _ = s.Record(context.Background(), tid, fid, nil, Evidence{Summary: "c"})

	list, err := s.ListForFinding(context.Background(), tid, fid)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 records for finding, got %d", len(list))
	}
}
