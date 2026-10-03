// Package dnsprobe is a small, bounded DNS client for EASM's passive checks
// (RFC-036 P1: dangling DNS, email posture). It sends single questions to one
// configured recursive resolver and returns the raw answer — response code and
// records — which net.Resolver hides: a dangling CNAME is exactly the case
// where the resolver answers NXDOMAIN *with* the CNAME in the answer section,
// and net.Resolver reports only "no such host".
//
// Every query is rate-limited (one limiter per client, shared by all tenants),
// bounded in time, retried once over TCP when the UDP answer is truncated, and
// never follows anything by itself: callers decide which name to ask next.
package dnsprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/time/rate"
)

// RCode is a DNS response code.
type RCode = dnsmessage.RCode

// Response codes the checks care about.
const (
	RCodeSuccess  = dnsmessage.RCodeSuccess
	RCodeNXDomain = dnsmessage.RCodeNameError
	RCodeServFail = dnsmessage.RCodeServerFailure
	RCodeRefused  = dnsmessage.RCodeRefused
)

// Type is a DNS record type.
type Type = dnsmessage.Type

// Record types the checks ask for.
const (
	TypeA     = dnsmessage.TypeA
	TypeAAAA  = dnsmessage.TypeAAAA
	TypeCNAME = dnsmessage.TypeCNAME
	TypeNS    = dnsmessage.TypeNS
	TypeTXT   = dnsmessage.TypeTXT
	TypeMX    = dnsmessage.TypeMX
)

// Record is one answer record, reduced to what the checks read.
type Record struct {
	Name  string // owner name, lowercase, no trailing dot
	Type  Type
	Value string   // CNAME/NS target or A/AAAA address, lowercase, no trailing dot
	TXT   []string // TXT strings (joined by the caller as needed)
}

// Answer is the outcome of one question.
type Answer struct {
	RCode   RCode
	Records []Record
}

// Has reports whether the answer has a record of type t.
func (a Answer) Has(t Type) bool {
	for _, r := range a.Records {
		if r.Type == t {
			return true
		}
	}
	return false
}

// ErrTimeout is returned when the resolver did not answer in time.
var ErrTimeout = errors.New("dns: timeout")

// Config configures a Client.
type Config struct {
	// Server is the recursive resolver as host:port. Empty means the first
	// nameserver in /etc/resolv.conf, port 53.
	Server string
	// QPS bounds queries per second across all callers (default 20).
	QPS float64
	// Timeout bounds one query (default 3 s).
	Timeout time.Duration
}

// Client asks one resolver one question at a time.
type Client struct {
	server  string
	limiter *rate.Limiter
	timeout time.Duration
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New builds a client. It fails only when no resolver can be determined.
func New(cfg Config) (*Client, error) {
	server := strings.TrimSpace(cfg.Server)
	if server == "" {
		s, err := systemResolver("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		server = s
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	qps := cfg.QPS
	if qps <= 0 {
		qps = 20
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	return &Client{
		server:  server,
		limiter: rate.NewLimiter(rate.Limit(qps), max(1, int(qps))),
		timeout: timeout,
		dial:    d.DialContext,
	}, nil
}

// Server returns the resolver address in use.
func (c *Client) Server() string { return c.server }

// systemResolver reads the first nameserver of a resolv.conf.
func systemResolver(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // fixed system path (tests pass a temp file)
	if err != nil {
		return "", fmt.Errorf("dns: no resolver configured and %s unreadable: %w", path, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			return net.JoinHostPort(f[1], "53"), nil
		}
	}
	return "", fmt.Errorf("dns: no nameserver in %s", path)
}

// Query asks one question. A non-success RCode is not an error: NXDOMAIN is
// an answer the checks need. Errors are transport problems and timeouts.
func (c *Client) Query(ctx context.Context, name string, t Type) (Answer, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return Answer{}, err
	}
	q, id, err := buildQuery(name, t)
	if err != nil {
		return Answer{}, err
	}
	ans, truncated, err := c.exchange(ctx, "udp", q, id)
	if err == nil && truncated {
		ans, _, err = c.exchange(ctx, "tcp", q, id)
	}
	return ans, err
}

func buildQuery(name string, t Type) ([]byte, uint16, error) {
	fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".") + "."
	n, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, 0, fmt.Errorf("dns: invalid name %q: %w", name, err)
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: t, Class: dnsmessage.ClassINET}},
	}
	b, err := msg.Pack()
	return b, id, err
}

func (c *Client) exchange(ctx context.Context, network string, q []byte, id uint16) (Answer, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, err := c.dial(ctx, network, c.server)
	if err != nil {
		return Answer{}, false, fmt.Errorf("dns: dial %s: %w", c.server, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	var buf []byte
	if network == "tcp" {
		framed := make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(framed, uint16(len(q))) //nolint:gosec // a DNS query is far below 64 KiB
		copy(framed[2:], q)
		if _, err := conn.Write(framed); err != nil {
			return Answer{}, false, wrapNetErr(err)
		}
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return Answer{}, false, wrapNetErr(err)
		}
		buf = make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return Answer{}, false, wrapNetErr(err)
		}
	} else {
		if _, err := conn.Write(q); err != nil {
			return Answer{}, false, wrapNetErr(err)
		}
		buf = make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return Answer{}, false, wrapNetErr(err)
			}
			// Ignore stray datagrams with another id (spoofing, late answers).
			if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == id {
				buf = buf[:n]
				break
			}
		}
	}
	return parse(buf, id)
}

func wrapNetErr(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrTimeout
	}
	return fmt.Errorf("dns: %w", err)
}

// maxRecords bounds how many answer records are read from one response.
const maxRecords = 64

func parse(b []byte, id uint16) (Answer, bool, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return Answer{}, false, fmt.Errorf("dns: malformed answer: %w", err)
	}
	if h.ID != id || !h.Response {
		return Answer{}, false, errors.New("dns: answer does not match the question")
	}
	if h.Truncated {
		return Answer{}, true, nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return Answer{}, false, fmt.Errorf("dns: malformed answer: %w", err)
	}
	ans := Answer{RCode: h.RCode}
	for i := 0; i < maxRecords; i++ {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return Answer{}, false, fmt.Errorf("dns: malformed answer: %w", err)
		}
		rec := Record{Name: clean(rh.Name.String()), Type: rh.Type}
		switch rh.Type {
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				return Answer{}, false, err
			}
			rec.Value = clean(r.CNAME.String())
		case dnsmessage.TypeNS:
			r, err := p.NSResource()
			if err != nil {
				return Answer{}, false, err
			}
			rec.Value = clean(r.NS.String())
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return Answer{}, false, err
			}
			rec.Value = net.IP(r.A[:]).String()
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return Answer{}, false, err
			}
			rec.Value = net.IP(r.AAAA[:]).String()
		case dnsmessage.TypeMX:
			r, err := p.MXResource()
			if err != nil {
				return Answer{}, false, err
			}
			rec.Value = clean(r.MX.String())
		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return Answer{}, false, err
			}
			rec.TXT = r.TXT
		default:
			if err := p.SkipAnswer(); err != nil {
				return Answer{}, false, err
			}
			continue
		}
		ans.Records = append(ans.Records, rec)
	}
	return ans, false, nil
}

func clean(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
