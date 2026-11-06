package email

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func readQP(t *testing.T, p *multipart.Part) string {
	t.Helper()
	// mime/multipart decodes quoted-printable parts itself.
	b, err := io.ReadAll(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parse(t *testing.T, raw []byte) *mail.Message {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("message does not parse: %v\n%s", err, raw)
	}
	return m
}

func htmlMsg(body string) *Message {
	return &Message{To: []string{"u@example.org"}, Subject: "Hi", Body: body, IsHTML: true}
}

func TestBuildMessage_RequiredHeaders(t *testing.T) {
	fixed := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	nowFunc = func() time.Time { return fixed }
	t.Cleanup(func() { nowFunc = time.Now })

	s := NewSMTPSender(Config{From: "no-reply@mail.example.com", FromName: "OpenCTEM"})
	m := parse(t, s.buildMessage(htmlMsg("<p>x</p>")))

	d, err := m.Header.Date()
	if err != nil || !d.Equal(fixed) {
		t.Errorf("Date = %v (%v), want %v", d, err, fixed)
	}
	id := m.Header.Get("Message-ID")
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@mail.example.com>") {
		t.Errorf("Message-ID = %q, want one on the From domain", id)
	}
	other := parse(t, s.buildMessage(htmlMsg("<p>x</p>"))).Header.Get("Message-ID")
	if other == id {
		t.Error("two messages share a Message-ID")
	}
	if got := m.Header.Get("Auto-Submitted"); got != "auto-generated" {
		t.Errorf("Auto-Submitted = %q", got)
	}
	if got := m.Header.Get("MIME-Version"); got != "1.0" {
		t.Errorf("MIME-Version = %q", got)
	}
}

func TestBuildMessage_VietnameseSubjectAndNameRoundTrip(t *testing.T) {
	subject := "Bạn được mời tham gia Công ty Cổ phần An ninh mạng Việt Nam và nhiều tổ chức khác nữa"
	s := NewSMTPSender(Config{From: "no-reply@example.com", FromName: "Trung tâm Giám sát"})
	raw := s.buildMessage(&Message{To: []string{"u@example.org"}, Subject: subject, Body: "x"})

	if !strings.Contains(string(raw), "=?UTF-8?q?") && !strings.Contains(string(raw), "=?UTF-8?Q?") {
		t.Fatalf("subject is not RFC 2047 encoded:\n%s", raw)
	}
	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 78 {
			t.Errorf("header line of %d characters: %q", len(line), line)
		}
		for i := 0; i < len(line); i++ {
			if line[i] >= 0x80 {
				t.Fatalf("raw non-ASCII byte in %q", line)
			}
		}
	}
	m := parse(t, raw)
	dec := new(mime.WordDecoder)
	got, err := dec.DecodeHeader(m.Header.Get("Subject"))
	if err != nil || got != subject {
		t.Errorf("subject round trip = %q (%v)", got, err)
	}
	from, err := m.Header.AddressList("From")
	if err != nil || len(from) != 1 || from[0].Name != "Trung tâm Giám sát" || from[0].Address != "no-reply@example.com" {
		t.Errorf("From = %+v (%v)", from, err)
	}
}

func TestBuildMessage_ASCIISubjectUnchanged(t *testing.T) {
	s := NewSMTPSender(Config{From: "a@example.com"})
	raw := string(s.buildMessage(&Message{To: []string{"u@example.org"}, Subject: "Reset your password", Body: "x"}))
	if !strings.Contains(raw, "\r\nSubject: Reset your password\r\n") {
		t.Errorf("ASCII subject was altered:\n%s", raw)
	}
}

func TestBuildMessage_AlternativeStructure(t *testing.T) {
	s := NewSMTPSender(Config{From: "a@example.com"})
	body := `<html><head><style>p{color:red}</style></head><body><p>Hello &amp; welcome</p><p><a href="https://app.example.com/set?t=abc">Set password</a></p></body></html>`
	m := parse(t, s.buildMessage(htmlMsg(body)))
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q (%v)", m.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var types, texts []string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		types = append(types, strings.SplitN(p.Header.Get("Content-Type"), ";", 2)[0])
		texts = append(texts, readQP(t, p))
	}
	if len(types) != 2 || types[0] != "text/plain" || types[1] != "text/html" {
		t.Fatalf("parts = %v, want text/plain then text/html", types)
	}
	if !strings.Contains(texts[0], "Hello & welcome") || !strings.Contains(texts[0], "Set password (https://app.example.com/set?t=abc)") {
		t.Errorf("text part lost content or link:\n%s", texts[0])
	}
	if strings.Contains(texts[0], "color:red") || strings.Contains(texts[0], "<") {
		t.Errorf("text part still has markup:\n%s", texts[0])
	}
	if texts[1] != body {
		t.Errorf("html part does not round-trip")
	}
}

func TestBuildMessage_ExplicitTextBody(t *testing.T) {
	s := NewSMTPSender(Config{From: "a@example.com"})
	msg := htmlMsg("<p>x</p>")
	msg.TextBody = "custom text"
	if raw := string(s.buildMessage(msg)); !strings.Contains(raw, "custom text") {
		t.Error("TextBody not used")
	}
}

func TestBuildMessage_LongHTMLLineIsQPWrapped(t *testing.T) {
	s := NewSMTPSender(Config{From: "a@example.com"})
	long := "<p>" + strings.Repeat("a", 2000) + " é</p>"
	raw := s.buildMessage(htmlMsg(long))
	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 78 {
			t.Fatalf("line of %d octets, want at most 78", len(line))
		}
	}
	m := parse(t, raw)
	_, params, _ := mime.ParseMediaType(m.Header.Get("Content-Type"))
	mr := multipart.NewReader(m.Body, params["boundary"])
	_, _ = mr.NextPart()
	p, _ := mr.NextPart()
	if got := readQP(t, p); got != long {
		t.Error("QP html part does not decode to the original")
	}
}

func TestBuildMessage_PlainTextIsQP(t *testing.T) {
	s := NewSMTPSender(Config{From: "a@example.com"})
	m := parse(t, s.buildMessage(&Message{To: []string{"u@example.org"}, Subject: "s", Body: "xin chào"}))
	if m.Header.Get("Content-Type") != "text/plain; charset=UTF-8" || m.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Errorf("headers %v", m.Header)
	}
	b, _ := io.ReadAll(quotedprintable.NewReader(m.Body))
	if strings.TrimSpace(string(b)) != "xin chào" {
		t.Errorf("body = %q", b)
	}
}

// CR and LF in any value are removed before the value is encoded, so none of
// them can start another header or end the header block.
func TestBuildMessage_HeaderInjectionRefused(t *testing.T) {
	evil := "x\r\nBcc: victim@example.net\r\n\r\nbody"
	s := NewSMTPSender(Config{From: "a@example.com", FromName: "N" + evil})
	raw := s.buildMessage(&Message{
		To: []string{"u@example.org" + evil}, Subject: "S" + evil, ReplyTo: "r@example.com" + evil,
		Body: "b", Headers: map[string]string{"X-A" + evil: "v" + evil, "X-Ok": "v" + evil},
	})
	head := string(raw)
	head = head[:strings.Index(head, "\r\n\r\n")]
	m := parse(t, raw)
	for _, forbidden := range []string{"Bcc", "bcc"} {
		if m.Header.Get(forbidden) != "" {
			t.Fatalf("injected %s header", forbidden)
		}
	}
	if strings.Count(head, "\r\n") != len(m.Header)+strings.Count(head, "\r\n ")-1 {
		// every header is one logical line: no stray line starts a new header.
		for _, l := range strings.Split(head, "\r\n") {
			if strings.HasPrefix(strings.ToLower(l), "bcc:") {
				t.Fatalf("injected line %q", l)
			}
		}
	}
	// Custom headers cannot override ones the builder writes.
	raw = s.buildMessage(&Message{To: []string{"u@example.org"}, Subject: "s", Body: "b",
		Headers: map[string]string{"Date": "forged", "Content-Type": "text/evil", "Bad Key": "v"}})
	if strings.Contains(string(raw), "forged") || strings.Contains(string(raw), "text/evil") || strings.Contains(string(raw), "Bad Key") {
		t.Error("a custom header overrode a builder header")
	}
}

func TestBuildMessage_AutoSubmittedOverridable(t *testing.T) {
	s := NewSMTPSender(Config{From: "a@example.com"})
	msg := htmlMsg("x")
	msg.Headers = map[string]string{"auto-submitted": "auto-notified"}
	m := parse(t, s.buildMessage(msg))
	if got := m.Header["Auto-Submitted"]; len(got) != 1 || got[0] != "auto-notified" {
		t.Errorf("Auto-Submitted = %v", got)
	}
}

func TestHTMLToText(t *testing.T) {
	got := HTMLToText("<h1>Title</h1><p>a<br>b</p><script>x()</script><a href=\"https://e.example/x\">https://e.example/x</a>")
	if got != "Title\n\na\nb\n\nhttps://e.example/x\n" {
		t.Errorf("got %q", got)
	}
}
