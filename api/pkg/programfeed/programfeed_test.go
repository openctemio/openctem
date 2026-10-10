package programfeed_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/programfeed"
	"github.com/openctemio/openctem/api/pkg/programfeed/programfeedtest"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func records() []map[string]any {
	return []map[string]any{
		programfeedtest.Record("acme-bounty", "acme", []string{"*.acme.example", "api.acme.example"}, []string{"admin.acme.example"}, now),
		programfeedtest.Record("acme-bounty", "beta", []string{"beta.example"}, nil, now),
	}
}

func TestVerifyAndRead(t *testing.T) {
	b := programfeedtest.New(t, now)
	dir := b.Write(t, 7, records())
	v, err := programfeed.VerifyDir(dir, programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	progs, err := v.ReadPrograms(programfeed.V1{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(progs) != 2 || progs[0].FeedID != "acme-bounty:acme" || progs[0].Sequence != 7 || len(progs[0].TermsSHA256) != 64 {
		t.Fatalf("programs = %+v", progs)
	}
}

func TestVerifyRefusals(t *testing.T) {
	b := programfeedtest.New(t, now)
	good := func() string { return b.Write(t, 7, records()) }
	opt := programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now}

	cases := map[string]func() (string, programfeed.Options){
		"wrong pinned root": func() (string, programfeed.Options) {
			o := opt
			o.PinnedRoot = programfeedtest.New(t, now).RootKeyID()
			return good(), o
		},
		"key set rolled back": func() (string, programfeed.Options) {
			o := opt
			o.MinKeySetVersion = 2
			return good(), o
		},
		"not newer": func() (string, programfeed.Options) {
			o := opt
			o.AppliedSequence = 7
			return good(), o
		},
		"expired": func() (string, programfeed.Options) {
			o := opt
			o.Now = now.Add(72 * time.Hour)
			return good(), o
		},
		"tampered records": func() (string, programfeed.Options) {
			d := good()
			p := filepath.Join(d, programfeed.ProgramsFile)
			raw, _ := os.ReadFile(p)
			raw[len(raw)-1] ^= 0xff
			_ = os.WriteFile(p, raw, 0o600)
			return d, opt
		},
		"pointer signed by another key": func() (string, programfeed.Options) {
			d := good()
			other := programfeedtest.New(t, now).Write(t, 7, records())
			raw, _ := os.ReadFile(filepath.Join(other, programfeed.LatestFile))
			_ = os.WriteFile(filepath.Join(d, programfeed.LatestFile), raw, 0o600)
			return d, opt
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			dir, o := mk()
			if _, err := programfeed.VerifyDir(dir, o); err == nil {
				t.Fatal("accepted")
			} else if name == "not newer" && !errors.Is(err, programfeed.ErrNotNewer) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestReadRefusesBadRecords(t *testing.T) {
	b := programfeedtest.New(t, now)
	bad := map[string]func(r map[string]any){
		"unknown field": func(r map[string]any) { r["cookie"] = "x" },
		"bad id":        func(r map[string]any) { r["id"] = "../../etc" },
		"id mismatch":   func(r map[string]any) { r["handle"] = "other" },
		"http url":      func(r map[string]any) { r["url"] = "http://x.example" },
		"no in scope":   func(r map[string]any) { r["in_scope"] = []map[string]string{} },
		"bad header": func(r map[string]any) {
			r["rules"] = map[string]any{"required_headers": []map[string]string{{"name": "Cookie", "value": "x"}}}
		},
		"missing as_of":  func(r map[string]any) { delete(r, "as_of") },
		"missing source": func(r map[string]any) { r["source"] = "" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			recs := records()
			mutate(recs[1])
			dir := b.Write(t, 9, recs)
			v, err := programfeed.VerifyDir(dir, programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if _, err := v.ReadPrograms(programfeed.V1{}); err == nil || !strings.Contains(err.Error(), "record 2") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A duplicate id is refused.
	recs := append(records(), records()[0])
	v, err := programfeed.VerifyDir(b.Write(t, 10, recs), programfeed.Options{PinnedRoot: b.RootKeyID(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadPrograms(programfeed.V1{}); err == nil {
		t.Fatal("duplicate accepted")
	}
}
