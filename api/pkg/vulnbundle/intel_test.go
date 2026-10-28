package vulnbundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func intelGz(t *testing.T, name string, lines ...string) ([]byte, *IntelStream) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(strings.Join(lines, "\n") + "\n"))
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), &IntelStream{Name: name, AsOf: time.Date(2026, 10, 26, 12, 3, 22, 0, time.UTC), Version: "v2025.03.14",
		File: File{Name: IntelFileName(name), SHA256: hex.EncodeToString(sum[:]), Size: int64(buf.Len()), Records: len(lines)}}
}

const (
	kevLine1 = `{"cve":"CVE-2021-44228","vendor":"Apache","product":"Log4j2","name":"RCE","description":"d","date_added":"2021-12-10","due_date":"2021-12-24","ransomware":"Known","cwes":["CWE-20","NVD-CWE-noinfo"]}`
	kevLine2 = `{"cve":"CVE-2022-0001","vendor":"V","product":"P","name":"N","description":"D","date_added":"2022-03-03","ransomware":"Unknown","cwes":[]}`
)

func TestParseIntelKEV(t *testing.T) {
	gz, s := intelGz(t, "kev", kevLine1, kevLine2)
	got, err := ParseIntelKEV(gz, s)
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	if got[0].CVEID() != "CVE-2021-44228" || got[0].KnownRansomwareCampaignUse() != "Known" || len(got[0].CWEs()) != 1 || got[0].CWEs()[0] != "CWE-20" {
		t.Fatalf("%+v", got[0])
	}
	if got[0].DueDate().Format("2006-01-02") != "2021-12-24" || !got[1].DueDate().IsZero() {
		t.Fatalf("due dates %v %v", got[0].DueDate(), got[1].DueDate())
	}
}

func TestParseIntelKEVRefusals(t *testing.T) {
	cases := map[string]struct {
		lines []string
		mut   func(*IntelStream)
	}{
		"unknown field":   {[]string{strings.Replace(kevLine1, `"cwes"`, `"extra":1,"cwes"`, 1)}, nil},
		"bad cve":         {[]string{strings.Replace(kevLine1, "CVE-2021-44228", "CVE-21-1", 1)}, nil},
		"unordered":       {[]string{kevLine2, kevLine1}, nil},
		"duplicate":       {[]string{kevLine1, kevLine1}, nil},
		"bad date":        {[]string{strings.Replace(kevLine1, "2021-12-10", "10/12/2021", 1)}, nil},
		"more than said":  {[]string{kevLine1, kevLine2}, func(s *IntelStream) { s.File.Records = 1 }},
		"fewer than said": {[]string{kevLine1}, func(s *IntelStream) { s.File.Records = 2 }},
		"hash":            {[]string{kevLine1}, func(s *IntelStream) { s.File.SHA256 = strings.Repeat("0", 64) }},
		"over the cap":    {[]string{kevLine1}, func(s *IntelStream) { s.File.Records = MaxIntelKEVRecords + 1 }},
		"long field":      {[]string{strings.Replace(kevLine1, `"d"`, `"`+strings.Repeat("x", 5000)+`"`, 1)}, nil},
	}
	for name, c := range cases {
		gz, s := intelGz(t, "kev", c.lines...)
		if c.mut != nil {
			c.mut(s)
		}
		if _, err := ParseIntelKEV(gz, s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	gz, s := intelGz(t, "kev", kevLine1)
	bad := append([]byte{}, gz...)
	bad[len(bad)-2] ^= 0xff
	if _, err := ParseIntelKEV(bad, s); err == nil {
		t.Error("a tampered file was accepted")
	}
}

func TestParseIntelEPSS(t *testing.T) {
	gz, s := intelGz(t, "epss", `{"cve":"CVE-2020-0001","epss":0.25,"percentile":0.5}`, `{"cve":"CVE-2020-0002","epss":1,"percentile":1}`)
	got, err := ParseIntelEPSS(gz, s)
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	// The published fraction becomes the stored 0-100 percentile, dated by day.
	if got[0].Percentile() != 50 || got[1].Percentile() != 100 || got[0].Score() != 0.25 || got[0].ModelVersion() != "v2025.03.14" ||
		got[0].ScoreDate().Format("2006-01-02") != "2026-10-26" {
		t.Fatalf("%v %v %v", got[0].Percentile(), got[0].ModelVersion(), got[0].ScoreDate())
	}
}

func TestParseIntelEPSSRefusals(t *testing.T) {
	ok1 := `{"cve":"CVE-2020-0001","epss":0.25,"percentile":0.5}`
	ok2 := `{"cve":"CVE-2020-0002","epss":0.25,"percentile":0.5}`
	cases := map[string][]string{
		"score above one":     {`{"cve":"CVE-2020-0001","epss":1.5,"percentile":0.5}`},
		"negative percentile": {`{"cve":"CVE-2020-0001","epss":0.5,"percentile":-0.1}`},
		"percentile on 0-100": {`{"cve":"CVE-2020-0001","epss":0.5,"percentile":50}`},
		"unordered":           {ok2, ok1},
		"duplicate":           {ok1, ok1},
		"bad id":              {`{"cve":"EPSS-1","epss":0.5,"percentile":0.5}`},
		"unknown field":       {strings.Replace(ok1, `"epss"`, `"x":1,"epss"`, 1)},
		"not json":            {"CVE-2020-0001,0.5,0.5"},
	}
	for name, lines := range cases {
		gz, s := intelGz(t, "epss", lines...)
		if _, err := ParseIntelEPSS(gz, s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func intelManifest(seq uint64, now time.Time, streams ...IntelStream) IntelManifest {
	return IntelManifest{Schema: IntelSchema, Sequence: seq, CreatedAt: now, ExpiresAt: now.Add(MaxBundleValidity), Streams: streams}
}

func TestVerifyIntelManifest(t *testing.T) {
	k := newTestKeys(t, 1)
	other := newTestKeys(t, 1)
	ks, err := VerifyKeySet(k.keyset, k.rootID, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	good := IntelStream{Name: "kev", AsOf: now.Add(-3 * time.Hour), FetchedAt: now, Version: "x", File: File{Name: "intel-kev.jsonl.gz", Size: 10, Records: 1}}
	unknown := IntelStream{Name: "exploits", AsOf: now, FetchedAt: now, File: File{Name: "intel-exploits.jsonl.gz"}}
	envelope := func(m IntelManifest) []byte {
		p, _ := json.Marshal(m)
		return sign(k.priv, IntelManifestPayloadType, p)
	}

	m, err := VerifyIntelManifest(ks, envelope(intelManifest(7, now, good, unknown)), 7, now)
	if err != nil || m.Stream("kev") == nil || m.Stream("exploits") == nil || m.Stream("epss") != nil {
		t.Fatalf("%v %v", m, err)
	}
	bad := map[string]struct {
		raw []byte
		seq uint64
		now time.Time
	}{
		"another sequence": {envelope(intelManifest(7, now, good)), 8, now},
		"expired":          {envelope(intelManifest(7, now, good)), 7, now.Add(8 * 24 * time.Hour)},
		"no streams":       {envelope(intelManifest(7, now)), 7, now},
		"another key set": {func() []byte {
			p, _ := json.Marshal(intelManifest(7, now, good))
			return sign(other.priv, IntelManifestPayloadType, p)
		}(), 7, now},
		"wrong type": {func() []byte {
			p, _ := json.Marshal(intelManifest(7, now, good))
			return sign(k.priv, VulnIDsManifestPayloadType, p)
		}(), 7, now},
	}
	mut := func(f func(*IntelStream)) []byte {
		s := good
		f(&s)
		return envelope(intelManifest(7, now, s))
	}
	bad["file of another stream"] = struct {
		raw []byte
		seq uint64
		now time.Time
	}{mut(func(s *IntelStream) { s.File.Name = "intel-epss.jsonl.gz" }), 7, now}
	bad["path in the name"] = struct {
		raw []byte
		seq uint64
		now time.Time
	}{mut(func(s *IntelStream) { s.Name = "../kev"; s.File.Name = "intel-../kev.jsonl.gz" }), 7, now}
	bad["data date in the future"] = struct {
		raw []byte
		seq uint64
		now time.Time
	}{mut(func(s *IntelStream) { s.AsOf = now.Add(30 * 24 * time.Hour) }), 7, now}
	bad["no fetch time"] = struct {
		raw []byte
		seq uint64
		now time.Time
	}{mut(func(s *IntelStream) { s.FetchedAt = time.Time{} }), 7, now}
	bad["fetch time in the future"] = struct {
		raw []byte
		seq uint64
		now time.Time
	}{mut(func(s *IntelStream) { s.FetchedAt = now.Add(3 * time.Hour) }), 7, now}
	dup := intelManifest(7, now, good, good)
	bad["repeated stream"] = struct {
		raw []byte
		seq uint64
		now time.Time
	}{envelope(dup), 7, now}
	for name, c := range bad {
		if _, err := VerifyIntelManifest(ks, c.raw, c.seq, c.now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
