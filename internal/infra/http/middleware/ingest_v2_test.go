package middleware

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/openctemio/api/pkg/logger"
	protov2 "github.com/openctemio/api/pkg/sensorproto/v2"
)

func sha256Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(s[:]) + ":"
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zstdBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(b, nil)
}

// edge is the read chain under test with a terminal handler that echoes the
// verified body.
func edge(limits protov2.Limits) http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := V2BodyFromContext(r.Context())
		if b == nil {
			http.Error(w, "no verified body", 599)
			return
		}
		w.Header().Set("X-Digest", b.Digest)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(b.Decoded)
	})
	var out http.Handler = h
	for _, mw := range []func(http.Handler) http.Handler{V2ReadVerified(limits), V2ContentEncoding(), V2ContentType()} {
		out = mw(out)
	}
	return out
}

func v2Request(body []byte, mutate func(*http.Request)) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/api/v2/sensor/results/x", bytes.NewReader(body))
	r.Header.Set("Content-Type", protov2.MediaTypeCTIS)
	r.Header.Set(protov2.HeaderContentDigest, sha256Digest(body))
	if mutate != nil {
		mutate(r)
	}
	return r
}

func problemType(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem body: %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != protov2.MediaTypeProblem {
		t.Fatalf("content type %q", rec.Header().Get("Content-Type"))
	}
	return strings.TrimPrefix(p.Type, protov2.ProblemTypeBase)
}

func TestV2Edge_Gates(t *testing.T) {
	limits := protov2.DefaultLimits()
	body := []byte(`{"version":"1.0"}`)
	gz := gzipBytes(t, body)

	cases := []struct {
		name    string
		req     *http.Request
		status  int
		problem string
	}{
		{"ok identity", v2Request(body, nil), 202, ""},
		{"ok gzip, digest over compressed bytes", v2Request(gz, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }), 202, ""},
		{"application/json", v2Request(body, func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }), 415, "unsupported-media-type"},
		{"no content type", v2Request(body, func(r *http.Request) { r.Header.Del("Content-Type") }), 415, "unsupported-media-type"},
		{"br", v2Request(body, func(r *http.Request) { r.Header.Set("Content-Encoding", "br") }), 415, "unsupported-encoding"},
		{"stacked codings", v2Request(gz, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip, gzip") }), 415, "unsupported-encoding"},
		{"no digest", v2Request(body, func(r *http.Request) { r.Header.Del(protov2.HeaderContentDigest) }), 400, "digest-required"},
		{"malformed digest", v2Request(body, func(r *http.Request) { r.Header.Set(protov2.HeaderContentDigest, "sha-256=abc") }), 400, "digest-required"},
		{"only unknown algorithm", v2Request(body, func(r *http.Request) { r.Header.Set(protov2.HeaderContentDigest, "md5=:AAAA:") }), 400, "digest-required"},
		{"digest mismatch", v2Request(body, func(r *http.Request) { r.Header.Set(protov2.HeaderContentDigest, sha256Digest([]byte("other"))) }), 400, "digest-mismatch"},
		{"digest over decompressed bytes", v2Request(gz, func(r *http.Request) {
			r.Header.Set("Content-Encoding", "gzip")
			r.Header.Set(protov2.HeaderContentDigest, sha256Digest(body))
		}), 400, "digest-mismatch"},
		{"one of two digests wrong", v2Request(body, func(r *http.Request) {
			s := sha512.Sum512([]byte("other"))
			r.Header.Set(protov2.HeaderContentDigest, sha256Digest(body)+", sha-512=:"+base64.StdEncoding.EncodeToString(s[:])+":")
		}), 400, "digest-mismatch"},
		{"chunked", v2Request(body, func(r *http.Request) { r.ContentLength = -1; r.TransferEncoding = []string{"chunked"} }), 411, "length-required"},
		{"declared too large", v2Request(body, func(r *http.Request) { r.ContentLength = limits.MaxContentBytes + 1 }), 413, "content-too-large"},
		{"body shorter than declared", v2Request(body, func(r *http.Request) { r.ContentLength = int64(len(body)) + 5 }), 400, "digest-mismatch"},
		{"body longer than declared", v2Request(body, func(r *http.Request) { r.ContentLength = int64(len(body)) - 2 }), 400, "digest-mismatch"},
		{"gzip header lies", v2Request(body, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }), 400, "invalid-encoding"},
		{"zstd header lies", v2Request(body, func(r *http.Request) { r.Header.Set("Content-Encoding", "zstd") }), 400, "invalid-encoding"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			edge(limits).ServeHTTP(rec, c.req)
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
			if c.problem != "" {
				if got := problemType(t, rec); got != c.problem {
					t.Fatalf("problem %q, want %q", got, c.problem)
				}
				if rec.Header().Get(protov2.HeaderProtocol) != "2" {
					t.Fatal("missing protocol header")
				}
				return
			}
			if !bytes.Equal(rec.Body.Bytes(), body) {
				t.Fatalf("decoded %q", rec.Body.String())
			}
		})
	}
}

func TestV2Edge_415CarriesAccept(t *testing.T) {
	rec := httptest.NewRecorder()
	edge(protov2.DefaultLimits()).ServeHTTP(rec, v2Request([]byte("{}"), func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }))
	if rec.Header().Get("Accept") != protov2.MediaTypeCTIS {
		t.Fatalf("Accept %q", rec.Header().Get("Accept"))
	}
	rec = httptest.NewRecorder()
	edge(protov2.DefaultLimits()).ServeHTTP(rec, v2Request([]byte("{}"), func(r *http.Request) { r.Header.Set("Content-Encoding", "br") }))
	if rec.Header().Get("Accept-Encoding") != "gzip, zstd" {
		t.Fatalf("Accept-Encoding %q", rec.Header().Get("Accept-Encoding"))
	}
}

// panicReader fails the test if the edge reads a body it should have refused
// from the headers alone.
type panicReader struct{ t *testing.T }

func (p panicReader) Read([]byte) (int, error) {
	p.t.Fatal("body read before the length/digest gates refused it")
	return 0, io.EOF
}

func TestV2Edge_OversizeRefusedBeforeRead(t *testing.T) {
	limits := protov2.DefaultLimits()
	for _, cl := range []int64{limits.MaxContentBytes + 1, 1 << 40} {
		r := httptest.NewRequest(http.MethodPut, "/x", io.NopCloser(panicReader{t}))
		r.ContentLength = cl
		r.Header.Set("Content-Type", protov2.MediaTypeCTIS)
		r.Header.Set(protov2.HeaderContentDigest, sha256Digest(nil))
		rec := httptest.NewRecorder()
		edge(limits).ServeHTTP(rec, r)
		if rec.Code != 413 || problemType(t, rec) != "content-too-large" {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
	}
	// No digest: refused before the body is read too.
	r := httptest.NewRequest(http.MethodPut, "/x", io.NopCloser(panicReader{t}))
	r.ContentLength = 10
	r.Header.Set("Content-Type", protov2.MediaTypeCTIS)
	rec := httptest.NewRecorder()
	edge(limits).ServeHTTP(rec, r)
	if rec.Code != 400 {
		t.Fatalf("got %d", rec.Code)
	}
}

// TestV2Edge_Bombs: a decompression bomb is refused with 413 and the process
// never holds more than the output cap, by absolute size and by ratio.
func TestV2Edge_Bombs(t *testing.T) {
	zeros := make([]byte, 96<<20) // 96 MiB of zeros
	gzBomb := gzipBytes(t, zeros)
	zstdBomb := zstdBytes(t, zeros)
	zeros = nil //nolint:ineffassign,staticcheck // released before measuring
	runtime.GC()

	small := protov2.DefaultLimits()
	small.MaxDecompressedBytes = 4 << 20
	// With the ratio cap out of the way, the absolute 64 MiB cap must stop
	// the 96 MiB bomb on its own.
	noRatio := protov2.DefaultLimits()
	noRatio.MaxCompressionRatio = 1e9

	cases := []struct {
		name     string
		encoding string
		body     []byte
		limits   protov2.Limits
	}{
		{"gzip default limits", "gzip", gzBomb, protov2.DefaultLimits()},
		{"zstd default limits", "zstd", zstdBomb, protov2.DefaultLimits()},
		{"gzip absolute", "gzip", gzBomb, noRatio},
		{"zstd absolute", "zstd", zstdBomb, noRatio},
		{"gzip ratio", "gzip", gzipBytes(t, make([]byte, 1<<20)), protov2.DefaultLimits()},
		{"zstd ratio", "zstd", zstdBytes(t, make([]byte, 1<<20)), protov2.DefaultLimits()},
		{"gzip small cap", "gzip", gzBomb, small},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			rec := httptest.NewRecorder()
			edge(c.limits).ServeHTTP(rec, v2Request(c.body, func(r *http.Request) { r.Header.Set("Content-Encoding", c.encoding) }))
			runtime.ReadMemStats(&after)
			if rec.Code != 413 || problemType(t, rec) != "decompressed-too-large" {
				t.Fatalf("got %d %s", rec.Code, rec.Body.String())
			}
			// Bounded: the decoder never produced more than the cap. Allow
			// the cap, the encoded copy, buffer growth and decoder state.
			allocated := after.TotalAlloc - before.TotalAlloc
			budget := uint64(c.limits.MaxDecompressedBytes)*3 + uint64(len(c.body))*2 + 32<<20
			if allocated > budget {
				t.Fatalf("allocated %d MiB, budget %d MiB", allocated>>20, budget>>20)
			}
		})
	}
}

func TestDecodeV2Content_RatioAllowsNormalCompression(t *testing.T) {
	// Real JSON compresses well below 100:1.
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		sb.WriteString(`{"title":"finding `)
		sb.WriteString(time.Duration(i).String())
		sb.WriteString(`","severity":"high","rule_id":"r-1"},`)
	}
	raw := []byte(sb.String())
	for _, enc := range []string{"gzip", "zstd"} {
		var in []byte
		if enc == "gzip" {
			in = gzipBytes(t, raw)
		} else {
			in = zstdBytes(t, raw)
		}
		out, err := DecodeV2Content(in, enc, protov2.DefaultLimits())
		if err != nil || !bytes.Equal(out, raw) {
			t.Fatalf("%s: %v", enc, err)
		}
	}
}

func TestV2Throttle(t *testing.T) {
	log := logger.NewNop()
	perTenant := NewTelemetryRateLimiter(1, 1, time.Minute, log)
	defer perTenant.Stop()
	perSensor := NewTelemetryRateLimiter(1, 1, time.Minute, log)
	defer perSensor.Stop()
	conc := NewTenantConcurrencyLimiter(1)

	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	h := V2Throttle(perTenant, perSensor, conc, func(r *http.Request) string { return r.Header.Get("X-Sensor") })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Block") != "" {
				entered <- struct{}{}
				<-release
			}
			w.WriteHeader(204)
		}))
	req := func(tenant, sensor string) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/x", nil)
		r.Header.Set("X-Sensor", sensor)
		if tenant != "" {
			r = r.WithContext(context.WithValue(r.Context(), TenantIDKey, tenant))
		}
		return r
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("t1", "s1"))
	if rec.Code != 204 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req("t1", "s2"))
	if rec.Code != 429 || problemType(t, rec) != "rate-limited" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("tenant bucket: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req("t2", "s1"))
	if rec.Code != 429 {
		t.Fatalf("sensor bucket: %d", rec.Code)
	}

	// Concurrency: one in flight per tenant.
	unlimited := V2Throttle(nil, nil, conc, func(*http.Request) string { return "" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Block") != "" {
				entered <- struct{}{}
				<-release
			}
			w.WriteHeader(204)
		}))
	blocked := req("t3", "")
	blocked.Header.Set("X-Block", "1")
	done := make(chan int)
	go func() {
		rec := httptest.NewRecorder()
		unlimited.ServeHTTP(rec, blocked)
		done <- rec.Code
	}()
	<-entered
	rec = httptest.NewRecorder()
	unlimited.ServeHTTP(rec, req("t3", ""))
	if rec.Code != 429 {
		t.Fatalf("concurrency: %d", rec.Code)
	}
	close(release)
	if code := <-done; code != 204 {
		t.Fatalf("blocked request: %d", code)
	}
	rec = httptest.NewRecorder()
	unlimited.ServeHTTP(rec, req("t3", ""))
	if rec.Code != 204 {
		t.Fatalf("after release: %d", rec.Code)
	}
}
