package commandlog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeStore struct {
	got Batch
	n   int
}

func (f *fakeStore) Append(_ context.Context, b Batch, after time.Duration, maxBatches, maxBytes int) (AppendResult, error) {
	f.got, f.n = b, f.n+1
	if after != AcceptAfterFinish || maxBatches != MaxBatchesPerCommand || maxBytes != MaxBytesPerCommand {
		return AppendResult{}, errors.New("limits not passed")
	}
	return AppendResult{Stored: len(b.Lines)}, nil
}

func (f *fakeStore) ListForRunTask(context.Context, shared.ID, shared.ID, shared.ID, int) (Page, error) {
	return Page{}, nil
}

func input(lines ...RawLine) AppendInput {
	return AppendInput{TenantID: shared.NewID(), SensorID: shared.NewID(), CommandID: shared.NewID(), Lines: lines}
}

func TestAppend_SanitizesAndRedacts(t *testing.T) {
	st := &fakeStore{}
	svc := NewService(st)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }

	secret := "octs_" + strings.Repeat("A", 32)
	_, err := svc.Append(context.Background(), input(
		RawLine{TS: "2026-10-05T11:59:00.5Z", Level: "WARNING", Msg: "key " + secret + " ‮evil\x1b[31m done", Source: "nuclei\nx",
			Fields: map[string]json.RawMessage{
				"auth":  json.RawMessage(`"Bearer abcdefghijklmnopqrstuvwxyz0123"`),
				"n":     json.RawMessage(`42`),
				"ok":    json.RawMessage(`true`),
				"obj":   json.RawMessage(`{"password":"hunter2"}`),
				"empty": json.RawMessage(`null`),
			}},
		RawLine{TS: "2099-01-01T00:00:00Z", Level: "nonsense", Msg: strings.Repeat("x", 20000)},
		RawLine{TS: "not a time", Level: "error"},
	))
	if err != nil {
		t.Fatal(err)
	}
	ls := st.got.Lines
	if len(ls) != 3 {
		t.Fatalf("lines %d", len(ls))
	}
	l := ls[0]
	if strings.Contains(l.Msg, secret) || !strings.Contains(l.Msg, "[REDACTED]") {
		t.Fatalf("sensor key not redacted: %q", l.Msg)
	}
	if strings.ContainsAny(l.Msg, "‮\x1b") {
		t.Fatalf("control or bidi character kept: %q", l.Msg)
	}
	if l.Level != LevelWarn || l.Source != "nuclei x" || !l.TS.Equal(time.Date(2026, 10, 5, 11, 59, 0, 500000000, time.UTC)) {
		t.Fatalf("line %+v", l)
	}
	if v := l.Fields["auth"].(string); strings.Contains(v, "abcdefghij") {
		t.Fatalf("bearer token not redacted: %q", v)
	}
	if l.Fields["n"] != float64(42) || l.Fields["ok"] != true || l.Fields["empty"] != "" {
		t.Fatalf("fields %+v", l.Fields)
	}
	if v := l.Fields["obj"].(string); strings.Contains(v, "hunter2") {
		t.Fatalf("object field not redacted: %q", v)
	}
	if ls[1].Level != LevelInfo || len(ls[1].Msg) > maxMsgBytes || !ls[1].TS.Equal(now) {
		t.Fatalf("future ts, unknown level or long msg: level %s len %d ts %s", ls[1].Level, len(ls[1].Msg), ls[1].TS)
	}
	if ls[2].Level != LevelError || !ls[2].TS.Equal(now) {
		t.Fatalf("bad ts line %+v", ls[2])
	}
	var decoded []Line
	if err := json.Unmarshal(st.got.JSON, &decoded); err != nil || len(decoded) != 3 {
		t.Fatalf("stored JSON %s: %v", st.got.JSON, err)
	}
}

func TestAppend_FieldsCapped(t *testing.T) {
	st := &fakeStore{}
	fields := map[string]json.RawMessage{}
	for i := 0; i < 50; i++ {
		fields[strings.Repeat("k", 200)+string(rune('a'+i%26))+string(rune('A'+i/26))] = json.RawMessage(`"` + strings.Repeat("v", 5000) + `"`)
	}
	if _, err := NewService(st).Append(context.Background(), input(RawLine{Msg: "m", Fields: fields})); err != nil {
		t.Fatal(err)
	}
	f := st.got.Lines[0].Fields
	if len(f) > maxFields {
		t.Fatalf("%d fields kept", len(f))
	}
	for k, v := range f {
		if len(k) > maxFieldKeyBytes || len(v.(string)) > maxFieldValBytes {
			t.Fatalf("field not capped: key %d value %d", len(k), len(v.(string)))
		}
	}
}

func TestAppend_RefusesBadBatches(t *testing.T) {
	st := &fakeStore{}
	svc := NewService(st)
	tooMany := make([]RawLine, MaxLinesPerBatch+1)
	cases := map[string]AppendInput{
		"negative seq":   func() AppendInput { in := input(RawLine{Msg: "m"}); in.Seq = -1; return in }(),
		"seq too large":  func() AppendInput { in := input(RawLine{Msg: "m"}); in.Seq = MaxSeq; return in }(),
		"too many lines": input(tooMany...),
		"no tenant":      func() AppendInput { in := input(RawLine{Msg: "m"}); in.TenantID = shared.ID{}; return in }(),
	}
	for name, in := range cases {
		if _, err := svc.Append(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v, want a validation error", name, err)
		}
	}
	if st.n != 0 {
		t.Fatalf("a refused batch reached the store")
	}
}

func TestListForRunTask_ZeroIDsNotFound(t *testing.T) {
	if _, err := NewService(&fakeStore{}).ListForRunTask(context.Background(), shared.ID{}, shared.NewID(), shared.NewID()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}
