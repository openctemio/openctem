// Package dnstest is a fake recursive resolver for tests: it answers from an
// in-memory zone the way a recursive resolver would (following CNAME chains
// and returning NXDOMAIN with the chain when the target does not exist), over
// UDP and TCP on a loopback port. It never forwards anything.
package dnstest

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// Entry is what the zone holds for one name.
type Entry struct {
	CNAME string
	A     []string
	AAAA  []string
	NS    []string
	MX    []string
	TXT   [][]string
	// RCode, when set, is returned for every question about this name
	// (for example dnsmessage.RCodeServerFailure).
	RCode dnsmessage.RCode
	// Truncate forces a truncated UDP answer so the client retries over TCP.
	Truncate bool
	// Referral answers like a parent zone's server: no answer, NOERROR, and
	// these name servers in the authority section.
	Referral []string
	// Authoritative sets the AA bit on answers for this name.
	Authoritative bool
}

// Server is a running fake resolver.
type Server struct {
	Addr string // host:port, same port for UDP and TCP

	mu      sync.Mutex
	zone    map[string]Entry
	queries []string
	udp     net.PacketConn
	tcp     net.Listener
}

// Start serves zone on 127.0.0.1 until Close.
func Start(zone map[string]Entry) (*Server, error) {
	return StartOn("127.0.0.1:0", zone)
}

// StartOn serves zone on addr (port 0 picks one).
func StartOn(addr string, zone map[string]Entry) (*Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	s := &Server{Addr: pc.LocalAddr().String(), zone: map[string]Entry{}, udp: pc, tcp: l}
	s.Set(zone)
	go s.serveUDP()
	go s.serveTCP()
	return s, nil
}

// Set replaces the zone.
func (s *Server) Set(zone map[string]Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zone = map[string]Entry{}
	for k, v := range zone {
		s.zone[norm(k)] = v
	}
}

// Queries returns the questions asked so far as "name TYPE".
func (s *Server) Queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// Close stops the server.
func (s *Server) Close() {
	_ = s.udp.Close()
	_ = s.tcp.Close()
}

func (s *Server) serveUDP() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if out := s.answer(buf[:n], true); out != nil {
			_, _ = s.udp.WriteTo(out, from)
		}
	}
}

func (s *Server) serveTCP() {
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			out := s.answer(q, false)
			if out == nil {
				return
			}
			framed := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(framed, uint16(len(out))) //nolint:gosec // test answers are small
			copy(framed[2:], out)
			_, _ = c.Write(framed)
		}(c)
	}
}

func norm(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }

func (s *Server) answer(q []byte, udp bool) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(q); err != nil || len(m.Questions) != 1 {
		return nil
	}
	question := m.Questions[0]
	name := norm(question.Name.String())

	s.mu.Lock()
	s.queries = append(s.queries, name+" "+strings.TrimPrefix(question.Type.String(), "Type"))
	zone := s.zone
	s.mu.Unlock()

	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: m.Questions,
	}
	cur := name
	for hops := 0; hops < 10; hops++ {
		e, ok := zone[cur]
		if !ok {
			resp.RCode = dnsmessage.RCodeNameError
			break
		}
		if e.RCode != 0 {
			resp.RCode = e.RCode
			break
		}
		if udp && e.Truncate && cur == name {
			resp.Truncated = true
			break
		}
		if len(e.Referral) > 0 {
			for _, n := range e.Referral {
				resp.Authorities = append(resp.Authorities, rr(cur, &dnsmessage.NSResource{NS: mustName(n)}))
			}
			break
		}
		resp.Authoritative = e.Authoritative
		if e.CNAME != "" {
			resp.Answers = append(resp.Answers, rr(cur, &dnsmessage.CNAMEResource{CNAME: mustName(e.CNAME)}))
			if question.Type == dnsmessage.TypeCNAME {
				break
			}
			cur = norm(e.CNAME)
			continue
		}
		switch question.Type {
		case dnsmessage.TypeA:
			for _, a := range e.A {
				ip := net.ParseIP(a).To4()
				var b [4]byte
				copy(b[:], ip)
				resp.Answers = append(resp.Answers, rr(cur, &dnsmessage.AResource{A: b}))
			}
		case dnsmessage.TypeAAAA:
			for _, a := range e.AAAA {
				var b [16]byte
				copy(b[:], net.ParseIP(a).To16())
				resp.Answers = append(resp.Answers, rr(cur, &dnsmessage.AAAAResource{AAAA: b}))
			}
		case dnsmessage.TypeNS:
			for _, n := range e.NS {
				resp.Answers = append(resp.Answers, rr(cur, &dnsmessage.NSResource{NS: mustName(n)}))
			}
		case dnsmessage.TypeMX:
			for i, n := range e.MX {
				resp.Answers = append(resp.Answers, rr(cur, &dnsmessage.MXResource{Pref: uint16(10 * (i + 1)), MX: mustName(n)})) //nolint:gosec // tiny test zones
			}
		case dnsmessage.TypeTXT:
			for _, t := range e.TXT {
				resp.Answers = append(resp.Answers, rr(cur, &dnsmessage.TXTResource{TXT: t}))
			}
		}
		break
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func mustName(s string) dnsmessage.Name {
	n, err := dnsmessage.NewName(norm(s) + ".")
	if err != nil {
		panic(err)
	}
	return n
}

func rr(name string, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: mustName(name), Class: dnsmessage.ClassINET, TTL: 60},
		Body:   body,
	}
}
