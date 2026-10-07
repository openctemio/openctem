package middleware

// Edge scan workflow of sensor protocol v2 results (RFC-026 §3.3,
// docs/rfcs/RFC-026-sensor-results-ingest.md).
//
// The chain runs after the sensor authenticator, in this order, each step
// cheaper than the next:
//
//	V2Throttle          per-tenant + per-sensor rate, per-tenant concurrency  429
//	V2ContentType       exactly application/vnd.openctem.ctis.v1+json        415
//	V2ContentEncoding   absent, gzip or zstd; one coding                     415
//	V2ReadVerified      Content-Length required and bounded            411 / 413
//	                    Content-Digest present, verified on the wire bytes   400
//	                    bounded decompression                          413 / 400
//
// Every refusal is an RFC 9457 problem from pkg/sensorproto/v2. A handler
// behind the chain never touches r.Body: it reads the verified, bounded
// content from V2BodyFromContext. A forged or damaged body never reaches the
// decompressor, and nothing is decompressed beyond the output cap.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/openctemio/openctem/api/internal/metrics"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// V2Body is the verified request content the v2 edge leaves in the context.
type V2Body struct {
	// Encoded is the content as received (what Content-Digest covers).
	Encoded []byte
	// Decoded is Encoded after the content coding was removed, bounded by
	// the limits. Equal to Encoded when there was no coding.
	Decoded []byte
	// Encoding is "", "gzip" or "zstd".
	Encoding string
	// Digest is the canonical sha-256 member of the received bytes. The
	// server computes it whatever algorithm the sensor declared; it is the
	// stored fingerprint and the idempotency comparison.
	Digest string
}

type v2BodyKey struct{}

// V2BodyFromContext returns the content V2ReadVerified verified, or nil.
func V2BodyFromContext(ctx context.Context) *V2Body {
	b, _ := ctx.Value(v2BodyKey{}).(*V2Body)
	return b
}

// WithV2Body stores a verified body in ctx. For tests of handlers that sit
// behind the edge.
func WithV2Body(ctx context.Context, b *V2Body) context.Context {
	return context.WithValue(ctx, v2BodyKey{}, b)
}

// V2ContentType refuses any Content-Type but the CTIS v1 media type (415 with
// Accept).
func V2ContentType() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if protov2.ParseResultsContentType(r.Header.Get("Content-Type")) != nil {
				protov2.NewProblem(protov2.ProblemUnsupportedMediaType).Write(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// V2ContentEncoding refuses a content coding other than gzip or zstd, or more
// than one (415 with Accept-Encoding).
func V2ContentEncoding() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := protov2.ParseContentEncoding(r.Header.Values("Content-Encoding")); err != nil {
				protov2.NewProblem(protov2.ProblemUnsupportedEncoding).Write(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// V2ReadVerified requires a bounded Content-Length, reads exactly that many
// bytes while hashing them, verifies Content-Digest on the bytes as sent, and
// only then removes the content coding with a bound. The result is stored for
// the handler (V2BodyFromContext).
//
// The global BodyLimit still wraps r.Body; a route that accepts more than it
// must install BodyLimit(limits.MaxContentBytes) before this middleware.
func V2ReadVerified(limits protov2.Limits) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Chunked or unknown length: refuse before reading (411).
			if r.ContentLength < 0 || hasChunked(r.TransferEncoding) {
				protov2.NewProblem(protov2.ProblemLengthRequired).Write(w)
				return
			}
			// Declared length over the limit: refuse before reading (413).
			if r.ContentLength > limits.MaxContentBytes {
				protov2.NewProblem(protov2.ProblemContentTooLarge).WithLimit(limits.MaxContentBytes).Write(w)
				return
			}
			digests, err := protov2.ParseContentDigest(r.Header.Values(protov2.HeaderContentDigest))
			if err != nil {
				protov2.NewProblem(protov2.ProblemDigestRequired).Write(w)
				return
			}
			encoding, err := protov2.ParseContentEncoding(r.Header.Values("Content-Encoding"))
			if err != nil {
				protov2.NewProblem(protov2.ProblemUnsupportedEncoding).Write(w)
				return
			}

			encoded, canonical, ok := readAndVerify(r, digests)
			if !ok {
				protov2.NewProblem(protov2.ProblemDigestMismatch).Write(w)
				return
			}

			decoded, err := DecodeV2Content(encoded, encoding, limits)
			switch {
			case errors.Is(err, ErrV2DecodedTooLarge):
				protov2.NewProblem(protov2.ProblemDecompressedTooLarge).WithLimit(limits.MaxDecompressedBytes).Write(w)
				return
			case err != nil:
				protov2.NewProblem(protov2.ProblemInvalidEncoding).Write(w)
				return
			}

			body := &V2Body{Encoded: encoded, Decoded: decoded, Encoding: encoding, Digest: canonical}
			next.ServeHTTP(w, r.WithContext(WithV2Body(r.Context(), body)))
		})
	}
}

// readAndVerify reads exactly r.ContentLength bytes, feeding every declared
// digest plus a sha-256 for the canonical fingerprint, and compares in
// constant time. A short body, a body longer than declared or any digest
// mismatch is ok=false: the bytes are not the ones the sensor described.
func readAndVerify(r *http.Request, digests protov2.Digests) (encoded []byte, canonical string, ok bool) {
	hashes := digests.NewDigestHashes()
	canon := sha256.New()
	writers := make([]io.Writer, 0, len(hashes)+1)
	writers = append(writers, canon)
	for _, h := range hashes {
		writers = append(writers, h)
	}

	buf := bytes.NewBuffer(make([]byte, 0, r.ContentLength))
	tee := io.TeeReader(io.LimitReader(r.Body, r.ContentLength), io.MultiWriter(writers...))
	n, err := io.Copy(buf, tee)
	if err != nil || n != r.ContentLength {
		return nil, "", false
	}
	// More bytes than declared means the framing lied; never trust it.
	var one [1]byte
	if extra, _ := r.Body.Read(one[:]); extra > 0 {
		return nil, "", false
	}

	for alg, want := range digests {
		if !digestEqual(hashes[alg], want) {
			return nil, "", false
		}
	}
	return buf.Bytes(), protov2.FormatSHA256(canon.Sum(nil)), true
}

func digestEqual(h hash.Hash, want []byte) bool {
	if h == nil {
		return false
	}
	return subtle.ConstantTimeCompare(h.Sum(nil), want) == 1
}

func hasChunked(te []string) bool {
	for _, v := range te {
		if strings.EqualFold(strings.TrimSpace(v), "chunked") {
			return true
		}
	}
	return false
}

// Decoding errors. ErrV2DecodedTooLarge maps to 413 decompressed-too-large;
// any other error to 400 invalid-encoding.
var (
	ErrV2DecodedTooLarge = errors.New("decoded content exceeds the size or ratio limit")
	ErrV2DecodeFailed    = errors.New("content does not decode with the declared coding")
)

// DecodeV2Content removes the content coding with three bounds: the decoded
// size, the compression ratio and, for zstd, the window size and decoder
// memory. The output cap is min(MaxDecompressedBytes, ratio × encoded size),
// so a bomb stops at the first byte past either limit and memory stays at the
// cap. The decoder runs with concurrency 1.
func DecodeV2Content(encoded []byte, encoding string, limits protov2.Limits) ([]byte, error) {
	maxOut := limits.MaxDecompressedBytes
	if encoding == "" {
		if int64(len(encoded)) > maxOut {
			return nil, ErrV2DecodedTooLarge
		}
		return encoded, nil
	}
	if limits.MaxCompressionRatio > 0 {
		byRatio := int64(limits.MaxCompressionRatio * float64(len(encoded)))
		if byRatio < maxOut {
			maxOut = byRatio
		}
	}

	var rd io.Reader
	switch encoding {
	case protov2.EncodingGzip:
		gz, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			return nil, ErrV2DecodeFailed
		}
		defer gz.Close()
		rd = gz
	case protov2.EncodingZstd:
		//nolint:gosec // G115: the limits are positive byte counts set by the server
		dec, err := zstd.NewReader(bytes.NewReader(encoded),
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(uint64(limits.MaxZstdWindowBytes)),
			zstd.WithDecoderMaxMemory(uint64(limits.MaxDecompressedBytes)))
		if err != nil {
			return nil, ErrV2DecodeFailed
		}
		defer dec.Close()
		rd = dec
	default:
		return nil, ErrV2DecodeFailed
	}

	out, err := readCapped(rd, maxOut)
	if err != nil {
		if errors.Is(err, ErrV2DecodedTooLarge) ||
			errors.Is(err, zstd.ErrWindowSizeExceeded) || errors.Is(err, zstd.ErrDecoderSizeExceeded) {
			return nil, ErrV2DecodedTooLarge
		}
		return nil, ErrV2DecodeFailed
	}
	return out, nil
}

// decodeChunk is the unit readCapped allocates in.
const decodeChunk = 256 << 10

// readCapped reads rd to EOF into fixed-size chunks and joins them once at
// the end, failing with ErrV2DecodedTooLarge at the first byte past maxOut.
// Unlike a doubling buffer it never allocates past the cap (a bytes.Buffer
// that reaches 64 MiB + 1 grows to 128 MiB), so a bomb costs at most the cap.
func readCapped(rd io.Reader, maxOut int64) ([]byte, error) {
	var (
		chunks [][]byte
		total  int64
	)
	for {
		chunk := make([]byte, decodeChunk)
		n, err := io.ReadFull(rd, chunk)
		total += int64(n)
		if total > maxOut {
			return nil, ErrV2DecodedTooLarge
		}
		if n > 0 {
			chunks = append(chunks, chunk[:n])
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out, nil
}

// V2Throttle applies the sensor-traffic bulkhead before any body byte is read
// (RFC-026 §3.3 step 3): the per-tenant rate, a per-sensor rate and the
// per-tenant in-flight cap. Refusals are 429 rate-limited problems with
// Retry-After. Any nil limiter is skipped; sensorKey returns the
// authenticated sensor id ("" skips the per-sensor bucket).
func V2Throttle(perTenant, perSensor *TelemetryRateLimiter, concurrency *TenantConcurrencyLimiter, sensorKey func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tid := GetTenantID(r.Context())
			if tid != "" && !perTenant.Allow(tid) {
				w.Header().Set(protov2.HeaderRetryAfter, "1")
				protov2.NewProblem(protov2.ProblemRateLimited).Write(w)
				return
			}
			if key := sensorKey(r); key != "" && !perSensor.Allow(key) {
				w.Header().Set(protov2.HeaderRetryAfter, "1")
				protov2.NewProblem(protov2.ProblemRateLimited).Write(w)
				return
			}
			if tid != "" {
				if !concurrency.TryAcquire(tid) {
					w.Header().Set(protov2.HeaderRetryAfter, "1")
					protov2.NewProblem(protov2.ProblemRateLimited).Write(w)
					return
				}
				defer concurrency.Release(tid)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// V2Observe records every answered v2 request in ingest_v2_requests_total:
// route (from routeName, a closed set), outcome (accepted for 202, ok for
// other 2xx, refused otherwise) and the problem type the response carried.
// It wraps the whole group, so refusals of the authenticator and the edge
// chain are counted too. No label ever holds a sensor-supplied string.
func V2Observe(routeName func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &v2Recorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			outcome := "refused"
			switch {
			case rec.status == http.StatusAccepted:
				outcome = "accepted"
			case rec.status >= 200 && rec.status < 300:
				outcome = "ok"
			}
			problem := string(rec.problem)
			if problem == "" {
				problem = "none"
			}
			method := r.Method
			switch method {
			case http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete:
			default:
				method = "other"
			}
			route := routeName(r)
			metrics.IngestV2RequestsTotal.WithLabelValues(route, method, outcome, problem).Inc()
			metrics.SensorProtocolRequestsTotal.WithLabelValues("2", route).Inc()
		})
	}
}

// v2Recorder captures the status and the problem type of a v2 response. It
// does not wrap Write: a body written without WriteHeader is a 200, which is
// the recorder's default, and net/http ignores a later WriteHeader anyway.
type v2Recorder struct {
	http.ResponseWriter
	status  int
	problem protov2.ProblemType
	wrote   bool
}

func (r *v2Recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

// RecordProblem implements protov2.ProblemRecorder.
func (r *v2Recorder) RecordProblem(t protov2.ProblemType) { r.problem = t }
