package importmapping

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	dom "github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// memRepo is a tenant-scoped in-memory Repository.
type memRepo struct {
	mu       sync.Mutex
	mappings map[shared.ID]*dom.Mapping
	versions map[shared.ID][]*dom.Version
}

func newMemRepo() *memRepo {
	return &memRepo{mappings: map[shared.ID]*dom.Mapping{}, versions: map[shared.ID][]*dom.Version{}}
}

var errNotFound = shared.ErrNotFound

func (r *memRepo) Create(_ context.Context, m *dom.Mapping, v *dom.Version) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.mappings {
		if o.TenantID == m.TenantID && o.Name == m.Name {
			return shared.ErrConflict
		}
	}
	c := *m
	r.mappings[m.ID] = &c
	r.versions[m.ID] = []*dom.Version{v}
	return nil
}

func (r *memRepo) List(_ context.Context, tid shared.ID) ([]*dom.Mapping, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*dom.Mapping{}
	for _, m := range r.mappings {
		if m.TenantID == tid {
			c := *m
			out = append(out, &c)
		}
	}
	return out, nil
}

func (r *memRepo) Count(ctx context.Context, tid shared.ID) (int, error) {
	l, _ := r.List(ctx, tid)
	return len(l), nil
}

func (r *memRepo) Get(_ context.Context, tid, id shared.ID) (*dom.Mapping, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.mappings[id]
	if !ok || m.TenantID != tid {
		return nil, errNotFound
	}
	c := *m
	return &c, nil
}

func (r *memRepo) GetByName(_ context.Context, tid shared.ID, name string) (*dom.Mapping, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.mappings {
		if m.TenantID == tid && m.Name == name {
			c := *m
			return &c, nil
		}
	}
	return nil, errNotFound
}

func (r *memRepo) GetVersion(_ context.Context, tid, id shared.ID, version int) (*dom.Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.mappings[id]
	if !ok || m.TenantID != tid {
		return nil, errNotFound
	}
	if version == 0 {
		version = m.LatestVersion
	}
	for _, v := range r.versions[id] {
		if v.Version == version {
			return v, nil
		}
	}
	return nil, errNotFound
}

func (r *memRepo) ListVersions(_ context.Context, tid, id shared.ID) ([]*dom.Version, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.mappings[id]; !ok || m.TenantID != tid {
		return nil, errNotFound
	}
	return r.versions[id], nil
}

func (r *memRepo) AddVersion(_ context.Context, v *dom.Version, expected int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.mappings[v.MappingID]
	if !ok || m.TenantID != v.TenantID {
		return errNotFound
	}
	if m.LatestVersion != expected {
		return shared.ErrConflict
	}
	m.LatestVersion = v.Version
	r.versions[v.MappingID] = append(r.versions[v.MappingID], v)
	return nil
}

func (r *memRepo) Update(_ context.Context, tid, id shared.ID, name, desc string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.mappings[id]
	if !ok || m.TenantID != tid {
		return errNotFound
	}
	m.Name, m.Description = name, desc
	return nil
}

func (r *memRepo) Delete(_ context.Context, tid, id shared.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.mappings[id]
	if !ok || m.TenantID != tid {
		return errNotFound
	}
	delete(r.mappings, id)
	return nil
}

const csvDoc = `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "identity": ["title", "asset_value"],
  "records": [{"kind": "finding", "set": {"title": "/title", "severity": {"path": "/severity", "lower": true}, "asset_value": "/host", "description": "/note"}}]}`

func TestCreateVersionsAndIdentityConfirm(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newMemRepo())
	tid := shared.NewID()
	m, v, err := svc.Create(ctx, CreateInput{TenantID: tid, Name: "legacy-vm", Document: json.RawMessage(csvDoc)})
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != 1 || m.Source != "csv" || strings.Join(v.Identity, ",") != "title,asset_value" || !strings.HasPrefix(v.Digest, "sha256:") {
		t.Fatalf("created %+v %+v", m, v)
	}
	if _, _, err := svc.Create(ctx, CreateInput{TenantID: tid, Name: "legacy-vm", Document: json.RawMessage(csvDoc)}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}

	// A cosmetic change saves without confirmation.
	cosmetic := strings.Replace(csvDoc, `"description": "/note"`, `"description": "/notes"`, 1)
	_, v2, err := svc.AddVersion(ctx, AddVersionInput{TenantID: tid, ID: m.ID, Document: json.RawMessage(cosmetic)})
	if err != nil || v2.Version != 2 || v2.IdentityChanged {
		t.Fatalf("cosmetic: %+v %v", v2, err)
	}
	// The same document again is refused.
	if _, _, err := svc.AddVersion(ctx, AddVersionInput{TenantID: tid, ID: m.ID, Document: json.RawMessage(cosmetic)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("same digest: %v", err)
	}
	// An identity change needs confirmation, never silently.
	rekey := strings.Replace(cosmetic, `"asset_value": "/host"`, `"asset_value": "/ip"`, 1)
	_, _, err = svc.AddVersion(ctx, AddVersionInput{TenantID: tid, ID: m.ID, Document: json.RawMessage(rekey)})
	var ic *IdentityChangeError
	if !errors.As(err, &ic) || !errors.Is(err, dom.ErrIdentityChangeUnconfirmed) {
		t.Fatalf("unconfirmed identity change: %v", err)
	}
	_, v3, err := svc.AddVersion(ctx, AddVersionInput{TenantID: tid, ID: m.ID, Document: json.RawMessage(rekey), ConfirmIdentityChange: true})
	if err != nil || v3.Version != 3 || !v3.IdentityChanged {
		t.Fatalf("confirmed: %+v %v", v3, err)
	}
	// Another source is another mapping.
	xml := `{"apiVersion": "openctem.io/mapping/v1", "source": "xml", "each": "//i", "identity": ["title"], "records": [{"kind": "finding", "set": {"title": "/@n", "severity": {"const": "low"}}}]}`
	if _, _, err := svc.AddVersion(ctx, AddVersionInput{TenantID: tid, ID: m.ID, Document: json.RawMessage(xml), ConfirmIdentityChange: true}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("source change: %v", err)
	}
	// A reserved member is refused at save.
	reserved := strings.Replace(csvDoc, `"description": "/note"`, `"fingerprint": "/id"`, 1)
	var ve *ValidationError
	if _, _, err := svc.AddVersion(ctx, AddVersionInput{TenantID: tid, ID: m.ID, Document: json.RawMessage(reserved), ConfirmIdentityChange: true}); !errors.As(err, &ve) {
		t.Fatalf("reserved: %v", err)
	}
	d, err := svc.Get(ctx, tid, m.ID, 0)
	if err != nil || d.Version.Version != 3 || len(d.Versions) != 3 {
		t.Fatalf("detail %+v %v", d, err)
	}
}

// A mapping is visible, resolvable and changeable only in its own
// organization: by id and by name, another organization gets not found.
func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newMemRepo())
	a, b := shared.NewID(), shared.NewID()
	m, _, err := svc.Create(ctx, CreateInput{TenantID: a, Name: "shared-name", Document: json.RawMessage(csvDoc)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, b, m.ID, 0); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get: %v", err)
	}
	for _, ref := range []string{m.ID.String(), "shared-name"} {
		if _, err := svc.Resolve(ctx, b, dom.FormatRef{Ref: ref}); !errors.Is(err, dom.ErrUnknownMapping) {
			t.Fatalf("resolve %s: %v", ref, err)
		}
	}
	if _, err := svc.PreviewVersion(ctx, b, m.ID, 0, strings.NewReader("title\nx\n")); !errors.Is(err, dom.ErrUnknownMapping) {
		t.Fatalf("preview: %v", err)
	}
	if _, _, err := svc.AddVersion(ctx, AddVersionInput{TenantID: b, ID: m.ID, Document: json.RawMessage(csvDoc)}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("add version: %v", err)
	}
	name := "taken"
	if _, err := svc.Update(ctx, b, m.ID, &name, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("update: %v", err)
	}
	if _, err := svc.Delete(ctx, b, m.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("delete: %v", err)
	}
	// The same name in another organization is a different mapping.
	if _, _, err := svc.Create(ctx, CreateInput{TenantID: b, Name: "shared-name", Document: json.RawMessage(csvDoc)}); err != nil {
		t.Fatalf("same name elsewhere: %v", err)
	}
	r, err := svc.Resolve(ctx, a, dom.FormatRef{Ref: "shared-name"})
	if err != nil || r.Mapping.ID != m.ID || r.Format() != "mapping:shared-name@1" || r.SourceName() != "mapped:shared-name" {
		t.Fatalf("resolve own: %+v %v", r, err)
	}
	if _, err := svc.Resolve(ctx, a, dom.FormatRef{Ref: "shared-name", Version: 9}); !errors.Is(err, dom.ErrUnknownMapping) {
		t.Fatalf("missing version: %v", err)
	}
}

func TestPreview(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newMemRepo())
	sample := "title,severity,host,note,extra\n" +
		"Weak TLS,High,a.example.com,n1,x\n" +
		"Weak TLS,high,a.example.com,n2,x\n" + // same identity: collides
		"Weak TLS,low,b.example.com,n3,x\n" +
		"\"=HYPERLINK(\"\"http://x.invalid\"\")\",low,c.example.com,,x\n"
	p, err := svc.PreviewDocument(ctx, json.RawMessage(csvDoc), strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if p.Stats.Findings != 4 || len(p.Items) != 4 {
		t.Fatalf("stats %+v", p.Stats)
	}
	if p.Items[0].IdentityKey == "" || p.Items[0].IdentityKey != p.Items[1].IdentityKey || p.Items[0].IdentityKey == p.Items[2].IdentityKey {
		t.Fatalf("identity keys %q %q %q", p.Items[0].IdentityKey, p.Items[1].IdentityKey, p.Items[2].IdentityKey)
	}
	if p.Items[0].Identity["asset_value"] != "a.example.com" || p.Items[0].Identity["title"] != "Weak TLS" {
		t.Fatalf("identity values %+v", p.Items[0].Identity)
	}
	codes := map[string]bool{}
	for _, w := range p.Warnings {
		codes[w.Code] = true
	}
	if !codes[WarnIdentityCollision] || !codes[WarnUnmapped] {
		t.Fatalf("warnings %+v", p.Warnings)
	}
	if strings.Join(p.Unmapped, ",") != "/extra" || len(p.Fields) != 5 {
		t.Fatalf("fields %v unmapped %v", p.Fields, p.Unmapped)
	}

	// Hostile samples are refused, never stored: XML with a DTD, and a
	// sample over the cap.
	xmlDoc := `{"apiVersion": "openctem.io/mapping/v1", "source": "xml", "each": "//i", "identity": ["title"], "records": [{"kind": "finding", "set": {"title": "/@n", "severity": {"const": "low"}}}]}`
	laughs := `<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><r><i n="&b;"/></r>`
	var ve *ValidationError
	if _, err := svc.PreviewDocument(ctx, json.RawMessage(xmlDoc), strings.NewReader(laughs)); !errors.As(err, &ve) {
		t.Fatalf("billion laughs: %v", err)
	}
	big := "title,severity,host\n" + strings.Repeat("t,low,h\n", MaxSampleBytes/8+10)
	if _, err := svc.PreviewDocument(ctx, json.RawMessage(csvDoc), strings.NewReader(big)); !errors.Is(err, ErrSampleTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	// An invalid document never runs.
	if _, err := svc.PreviewDocument(ctx, json.RawMessage(`{"apiVersion": "x"}`), strings.NewReader(sample)); !errors.As(err, &ve) {
		t.Fatalf("invalid: %v", err)
	}
}

func TestTemplatesCompile(t *testing.T) {
	ts, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 3 {
		t.Fatalf("templates %d", len(ts))
	}
	for _, tpl := range ts {
		if tpl.Name == "" || tpl.Source == "" || len(tpl.Mapping) == 0 {
			t.Fatalf("template %+v", tpl)
		}
	}
}

func TestValidate(t *testing.T) {
	svc := NewService(newMemRepo())
	if v := svc.Validate(json.RawMessage(csvDoc)); !v.Valid || v.Source != "csv" || len(v.Errors) != 0 {
		t.Fatalf("valid: %+v", v)
	}
	if v := svc.Validate(json.RawMessage(strings.Replace(csvDoc, `"description": "/note"`, `"baseline_state": "/x"`, 1))); v.Valid || len(v.Errors) == 0 {
		t.Fatalf("invalid: %+v", v)
	}
	if v := svc.Validate(nil); v.Valid {
		t.Fatal("empty is valid")
	}
}
