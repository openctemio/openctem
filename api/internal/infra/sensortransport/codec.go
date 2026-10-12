package sensortransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// v2Origin is the scheme and host of the in-process v2 requests. It is never
// resolved: the request goes straight to the in-process handler.
const v2Origin = "http://sensor-v3.internal"

// maxV2ResponseBytes bounds what the recorder keeps of a v2 answer (the
// largest is a claim list or a status resource, far below this).
const maxV2ResponseBytes = 32 << 20

// v2Call is one in-process protocol v2 request.
type v2Call struct {
	method string
	// path below protov2.PathPrefix, already validated ("/heartbeat").
	path   string
	query  url.Values
	header http.Header
	body   []byte
}

// v2Answer is a recorded v2 response.
type v2Answer struct {
	status int
	header http.Header
	body   []byte
}

// recorder is a minimal http.ResponseWriter that keeps the answer.
type recorder struct {
	header http.Header
	status int
	buf    bytes.Buffer
	over   bool
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if r.buf.Len()+len(b) > maxV2ResponseBytes {
		r.over = true
		return 0, errors.New("v2 answer too large")
	}
	return r.buf.Write(b)
}

// serveV2 runs c through the in-process v2 route group with the identity and
// peer of ctx.
func (s *Server) serveV2(ctx context.Context, c v2Call) (*v2Answer, error) {
	v2, _, _ := s.backend()
	if v2 == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("sensor protocol v3 is starting"))
	}
	u := v2Origin + protov2.PathPrefix + c.path
	if len(c.query) > 0 {
		u += "?" + c.query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, c.method, u, bytes.NewReader(c.body))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("request not built"))
	}
	if c.header != nil {
		req.Header = c.header
	}
	if len(c.body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", protov2.MediaTypeJSON)
	}
	peer := handler.SensorPeerFrom(ctx)
	if peer.UserAgent != "" {
		req.Header.Set("User-Agent", peer.UserAgent)
	}
	// The peer address the binding resolved (trusted-proxy rule applied).
	// No forwarding header is set, so the v2 code reads exactly this.
	req.RemoteAddr = net.JoinHostPort(peerHost(peer.IP), "0")
	rec := &recorder{header: http.Header{}}
	v2.ServeHTTP(rec, req)
	if rec.over {
		return nil, connect.NewError(connect.CodeInternal, errors.New("answer too large"))
	}
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	return &v2Answer{status: rec.status, header: rec.header, body: rec.buf.Bytes()}, nil
}

func peerHost(ip string) string {
	if net.ParseIP(ip) == nil {
		return "0.0.0.0"
	}
	return ip
}

// ok returns the answer when it is a success (2xx, or 304 when allowed),
// else the Connect error carrying the problem.
func (a *v2Answer) ok(allowNotModified bool) error {
	if a.status >= 200 && a.status < 300 || (allowNotModified && a.status == http.StatusNotModified) {
		return nil
	}
	return problemError(a.status, a.header, a.body)
}

// retryAfter is the Retry-After of the answer in seconds (0 when absent).
func (a *v2Answer) retryAfter() int32 {
	return retryAfterSeconds(a.header)
}

func retryAfterSeconds(h http.Header) int32 {
	v := strings.TrimSpace(h.Get(protov2.HeaderRetryAfter))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 3600 {
		return 0
	}
	return int32(n) //nolint:gosec // bounded above
}

// codeForStatus maps a v2 HTTP status to a Connect code (RFC-059 §4).
func codeForStatus(status int) connect.Code {
	switch status {
	case http.StatusBadRequest, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return connect.CodeInvalidArgument
	case http.StatusUnauthorized:
		return connect.CodeUnauthenticated
	case http.StatusForbidden:
		return connect.CodePermissionDenied
	case http.StatusNotFound, http.StatusGone:
		return connect.CodeNotFound
	case http.StatusConflict:
		return connect.CodeAborted
	case http.StatusPreconditionFailed:
		return connect.CodeFailedPrecondition
	case http.StatusRequestEntityTooLarge, http.StatusTooManyRequests:
		return connect.CodeResourceExhausted
	case http.StatusServiceUnavailable:
		return connect.CodeUnavailable
	case http.StatusGatewayTimeout:
		return connect.CodeDeadlineExceeded
	case http.StatusNotImplemented:
		return connect.CodeUnimplemented
	}
	if status >= 400 && status < 500 {
		return connect.CodeInvalidArgument
	}
	return connect.CodeInternal
}

// problemError is the Connect error of a refused v2 call: the code from the
// status, the problem's title as the message and the whole problem as a
// detail. The problem document is the v2 one: it never carries internal
// state (v2 already logs and hides that).
func problemError(status int, header http.Header, body []byte) *connect.Error {
	var p struct {
		Type  string `json:"type"`
		Title string `json:"title"`
	}
	if len(body) > 0 && len(body) <= 64<<10 {
		_ = json.Unmarshal(body, &p)
	} else {
		body = nil
	}
	msg := p.Title
	if msg == "" {
		msg = http.StatusText(status)
	}
	err := connect.NewError(codeForStatus(status), errors.New(msg))
	detail, derr := connect.NewErrorDetail(&sensorv3.Problem{
		HttpStatus:        int32(status), //nolint:gosec // an HTTP status
		Type:              p.Type,
		ProblemJson:       body,
		RetryAfterSeconds: retryAfterSeconds(header),
	})
	if derr == nil {
		err.AddDetail(detail)
	}
	return err
}

// invalid is an INVALID_ARGUMENT for a malformed envelope field.
func invalid(field string) *connect.Error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid "+field))
}

// validID checks an id that becomes a path segment: a UUID, nothing else.
func validID(v string) bool { return protov2.ValidateUUID(v) == nil }

// featureToken accepts a feature name: lower-case letters, digits, '_' and
// '-', at most 32 characters.
func featureToken(f string) bool {
	if f == "" || len(f) > 32 {
		return false
	}
	for i := 0; i < len(f); i++ {
		c := f[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
