package redact

import (
	"regexp"
	"strings"
	"testing"
)

func testRedactor() *Redactor { return NewWithKey([]byte("test key, fixed for stable marks")) }

// TestText_NastySamples: no part of a sensitive value survives, and what is
// not sensitive stays readable.
func TestText_NastySamples(t *testing.T) {
	cases := []struct {
		name string
		in   string
		gone []string // must not appear in the output
		kept []string // must appear in the output
	}{
		{"jwt", "token rejected: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			[]string{"eyJhbGci", "eyJzdWIi", "dozjgNry"}, []string{"rejected"}},
		{"bearer header", "Authorization: Bearer abcDEF123456ghiJKL7890", []string{"abcDEF123456ghiJKL7890"}, []string{"Authorization"}},
		{"bearer in text", "sent bearer s3cr3tT0kenValue99 upstream", []string{"s3cr3tT0kenValue99"}, []string{"upstream"}},
		{"basic auth header", `"authorization": "Basic dXNlcjpwYXNzd29yZA=="`, []string{"dXNlcjpwYXNzd29yZA"}, nil},
		{"cookie line", "Cookie: session=abc123def456; theme=dark", []string{"abc123def456", "theme=dark"}, []string{"Cookie"}},
		{"set-cookie", "< Set-Cookie: sid=ZZZ999YYY888; Path=/; HttpOnly", []string{"ZZZ999YYY888"}, nil},
		{"postgres url", "connect postgres://ctem_app:Sup3rS3cret!@db.internal.example:5432/ctem_prod?sslmode=require failed",
			[]string{"ctem_app", "Sup3rS3cret", "db.internal.example", "ctem_prod", "sslmode"}, []string{"connect", "failed"}},
		{"postgresql url without password", "postgresql://reader@10.20.30.40/reports", []string{"reader", "10.20.30.40", "reports"}, nil},
		{"redis url", "rediss://:r3disPassw0rd@cache.example.net:6380/2", []string{"r3disPassw0rd", "cache.example.net"}, nil},
		{"mongodb srv", "mongodb+srv://admin:hunter2222@cluster0.example.mongodb.net/app", []string{"admin:", "hunter2222", "cluster0"}, nil},
		{"amqp", "amqps://svc:Qu3ueP4ss@mq.example.org/vhost", []string{"Qu3ueP4ss", "mq.example.org"}, nil},
		{"key value dsn", "host=db01.corp.example user=ctem password=p4ssw0rdXYZ dbname=ctem_live sslmode=verify-full",
			[]string{"db01.corp.example", "user=ctem", "p4ssw0rdXYZ", "ctem_live"}, []string{"sslmode=verify-full"}},
		{"url with credentials", "fetch https://deploy:gh0stT0ken123@git.example.com/org/repo.git", []string{"deploy:", "gh0stT0ken123", "git.example.com"}, []string{"https://"}},
		{"url user only", "http://alice@files.example.com/", []string{"alice", "files.example.com"}, nil},
		{"url query", "GET /api/v1/assets?search=payroll-server&api_key=AbCdEf123456", []string{"payroll-server", "AbCdEf123456"}, []string{"/api/v1/assets"}},
		{"email plain", "invite sent to jane.doe@example.com", []string{"jane.doe", "example.com"}, []string{"invite sent to"}},
		{"email plus tag", "bob+alerts@mail.example.co.uk bounced", []string{"bob+alerts", "bob", "example.co.uk"}, []string{"bounced"}},
		{"email display name", `From: "Jane Doe" <jane@example.org>`, []string{"jane@", "example.org"}, nil},
		{"email encoded", "GET /verify/jane.doe%40example.com", []string{"jane.doe", "example.com"}, []string{"/verify/"}},
		{"email upper case", "JANE.DOE@EXAMPLE.COM", []string{"JANE", "EXAMPLE"}, nil},
		{"email quoted local", `"odd local"@example.com and "john..doe"@example.com`, []string{"john..doe", "example.com"}, nil},
		{"email internal domain", "root@mailhost failed", []string{"root@", "mailhost"}, []string{"failed"}},
		{"email in mailto", "mailto:sec-team@example.com?subject=hi", []string{"sec-team", "example.com"}, nil},
		{"email unicode", "jörg.müller@bücher.example", []string{"jörg", "müller", "bücher"}, nil},
		{"email subdomain", "a.b-c_d@x1.y2.example.io", []string{"a.b-c_d", "x1.y2"}, nil},
		{"ipv4", "dial tcp 192.0.2.17:5432: connect: connection refused", []string{"192.0.2.17"}, []string{"dial tcp", ":5432", "connection refused"}},
		{"ipv4 cidr", "range 198.51.100.0/24 excluded", []string{"198.51.100"}, []string{"excluded"}},
		{"ipv4 in brackets", "peer [203.0.113.9]", []string{"203.0.113.9"}, nil},
		{"ipv4 list", "10.0.0.1,10.0.0.2;172.16.5.4", []string{"10.0.0.1", "10.0.0.2", "172.16.5.4"}, nil},
		{"ipv6 full", "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 closed", []string{"2001:0db8", "8a2e", "7334"}, []string{"closed"}},
		{"ipv6 compressed", "from 2001:db8::8a2e:370:7334", []string{"2001:db8", "7334"}, nil},
		{"ipv6 bracket port", "listen [2001:db8::1]:8443", []string{"2001:db8::1"}, []string{":8443"}},
		{"ipv6 link local zone", "fe80::1ff:fe23:4567:890a%eth0 unreachable", []string{"fe80::1ff", "890a"}, []string{"unreachable"}},
		{"ipv6 mapped v4", "::ffff:192.0.2.128", []string{"192.0.2.128"}, nil},
		{"ipv6 then colon", "lookup 2001:db8::53: timeout", []string{"2001:db8::53"}, []string{"timeout"}},
		{"host name", "lookup scanme.example.com on resolver: no such host", []string{"scanme", "example.com"}, []string{"no such host"}},
		{"internal host", "probe of build-07.corp.internal failed", []string{"build-07", "corp.internal"}, []string{"failed"}},
		{"host with port", "connect to api.example.net:8443 refused", []string{"api.example.net"}, []string{":8443"}},
		{"long hex", "digest 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 mismatch", []string{"9f86d081884c7d65"}, []string{"mismatch"}},
		{"hex key 64", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []string{"0123456789abcdef"}, nil},
		{"long base64", "blob QmFzZTY0RW5jb2RlZFNlY3JldFZhbHVlMTIzNDU2Nzg5MEFCQ0RFRkdISUo= end", []string{"QmFzZTY0RW5jb2Rl"}, []string{"end"}},
		{"base64url", "state=dGhpc19pc19hX3ZlcnlfbG9uZ19zdGF0ZV92YWx1ZV8xMjM0NTY3ODkw", []string{"dGhpc19pc19h"}, nil},
		{"platform api key", "key oct_9aB8cD7eF6gH5iJ4kL3mN2oP1 used", []string{"oct_9aB8", "9aB8cD7eF6"}, []string{"used"}},
		{"sensor key", "octs_ZyXwVuTsRqPoNmLkJiHgFeDcBa presented", []string{"ZyXwVuTsRq"}, nil},
		{"aws key id", "AKIAIOSFODNN7EXAMPLE", []string{"AKIAIOSFODNN7EXAMPLE"}, nil},
		{"github token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", []string{"ghp_abcdefghij"}, nil},
		{"password assignment", `password="correct horse" and passwd: hunter2hunter2`, []string{"hunter2hunter2"}, nil},
		{"json secret", `{"client_secret":"s3cr3t-Value-0001","n":1}`, []string{"s3cr3t-Value-0001"}, nil},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\nabc\n-----END RSA PRIVATE KEY-----", []string{"MIIEpAIBAAKCAQEA7"}, nil},
		// What must stay readable.
		{"file and line", "handler.go:123 runtime.go:42 config.yaml 001146_baseline.up.sql", nil, []string{"handler.go:123", "runtime.go:42", "config.yaml", "001146_baseline.up.sql"}},
		{"module path", "github.com/openctemio/openctem/server/internal/app/scan.Trigger", nil, []string{"github.com/openctemio/openctem/server"}},
		{"module version", "github.com/lib/pq@v1.12.3/conn.go:88", nil, []string{"pq@v1.12.3/conn.go:88"}},
		{"image digest", "image ghcr.io/openctemio/openctem-server@sha256", nil, []string{"openctem-server@sha256"}},
		{"timestamps", "2026-11-17T10:21:33.123Z took 12:34:56", nil, []string{"2026-11-17T10:21:33.123Z", "12:34:56"}},
		{"uuid", "run 3f2504e0-4f89-41d3-9a0c-0305e82c3301 finished", nil, []string{"3f2504e0-4f89-41d3-9a0c-0305e82c3301"}},
		{"loopback", "listening on 127.0.0.1:8080 and [::1]:8080 and 0.0.0.0:9090", nil, []string{"127.0.0.1:8080", "[::1]:8080", "0.0.0.0:9090"}},
		{"versions", "server v0.23.0 go1.27.3 sensor 0.6.4", nil, []string{"v0.23.0", "go1.27.3"}},
	}
	r := testRedactor()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := r.Text(tc.in)
			for _, g := range tc.gone {
				if strings.Contains(strings.ToLower(out), strings.ToLower(g)) {
					t.Errorf("%q survived in %q", g, out)
				}
			}
			for _, k := range tc.kept {
				if !strings.Contains(out, k) {
					t.Errorf("%q lost from %q", k, out)
				}
			}
			if again := r.Text(out); again != out {
				t.Errorf("not idempotent:\n first %q\nsecond %q", out, again)
			}
		})
	}
}

// TestMarks_CorrelateWithinOneBundleOnly: the same value gets the same mark
// under one key and another mark under another key; the mark holds no part
// of the value.
func TestMarks_CorrelateWithinOneBundleOnly(t *testing.T) {
	r := testRedactor()
	a := r.Text("first 192.0.2.44 then 192.0.2.44 and 192.0.2.45")
	marks := regexp.MustCompile(`\[ip:[0-9a-f]{8}\]`).FindAllString(a, -1)
	if len(marks) != 3 || marks[0] != marks[1] || marks[0] == marks[2] {
		t.Fatalf("marks = %v in %q", marks, a)
	}
	other := NewWithKey([]byte("another bundle")).Text("first 192.0.2.44")
	if strings.Contains(other, marks[0]) {
		t.Fatalf("two bundles share the mark %s", marks[0])
	}
	fresh1, err := New()
	if err != nil {
		t.Fatal(err)
	}
	fresh2, _ := New()
	if fresh1.Mark(KindIP, "x") == fresh2.Mark(KindIP, "x") {
		t.Fatal("two new redactors share a key")
	}
	// The same address written two ways is one value.
	if x, y := r.Text("Jane@Example.com"), r.Text("jane%40example.com"); x != y {
		t.Fatalf("one address, two marks: %q %q", x, y)
	}
}

func TestMessage_DatabaseDetailsAndQuotedValues(t *testing.T) {
	r := testRedactor()
	cases := []struct {
		in   string
		gone []string
		kept []string
	}{
		{`pq: duplicate key value violates unique constraint "assets_tenant_name_key" DETAIL: Key (tenant_id, name)=(7b0e, Payroll Server 01) already exists.`,
			[]string{"Payroll Server 01", "7b0e"}, []string{`"assets_tenant_name_key"`, "Key (tenant_id, name)=", "already exists"}},
		{`null value in column "title" of relation "findings" violates not-null constraint DETAIL: Failing row contains (1, Acme Corp, SQL injection in login, null).`,
			[]string{"Acme Corp", "SQL injection in login"}, []string{`column "title"`, `relation "findings"`}},
		{`invalid input syntax for type uuid: "Payroll Server 01"`, []string{"Payroll Server 01"}, []string{"type uuid"}},
		{`asset 'Finance Laptop 7' not found`, []string{"Finance Laptop 7"}, []string{"not found"}},
		{`password authentication failed for user "ctem_owner"`, []string{"ctem_owner"}, []string{"password authentication failed"}},
		{`database "acme_ctem" does not exist`, []string{"acme_ctem"}, []string{"does not exist"}},
		{"statement: SELECT * FROM users WHERE email = 'jane@example.com' AND name = `Jane`", []string{"jane@example.com", "Jane`"}, []string{"SELECT * FROM users WHERE email ="}},
	}
	for _, tc := range cases {
		out := r.Message(tc.in)
		for _, g := range tc.gone {
			if strings.Contains(out, g) {
				t.Errorf("%q survived in %q", g, out)
			}
		}
		for _, k := range tc.kept {
			if !strings.Contains(out, k) {
				t.Errorf("%q lost from %q", k, out)
			}
		}
		if again := r.Message(out); again != out {
			t.Errorf("not idempotent: %q then %q", out, again)
		}
	}
}

func TestLogLine_Structured(t *testing.T) {
	r := testRedactor()
	cases := []struct {
		name string
		in   string
		gone []string
		kept []string
	}{
		{"request log",
			`{"time":"2026-11-17T10:00:00Z","level":"INFO","msg":"http request","method":"GET","path":"/api/v1/assets?search=payroll","status":200,"duration_ms":12,"remote_addr":"203.0.113.50:51123","user_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","user_agent":"Mozilla/5.0","request_id":"req-1"}`,
			[]string{"payroll", "203.0.113.50", "Mozilla"},
			[]string{`"msg":"http request"`, `"status":200`, `"duration_ms":12`, "3f2504e0-4f89-41d3-9a0c-0305e82c3301", `"method":"GET"`, "/api/v1/assets?", `"request_id":"req-1"`}},
		{"identity fields",
			`{"level":"WARN","msg":"login failed","email":"jane@example.com","username":"jdoe","tenant_name":"Acme Corp","tenant_slug":"acme","asset_name":"Payroll Server 01","hostname":"fileserver01","target":"intranet","finding_title":"SQL injection in login form"}`,
			[]string{"jane", "jdoe", "Acme", "acme", "Payroll", "fileserver01", "intranet", "SQL injection"},
			[]string{"login failed", `"email":"[value:`}},
		{"bodies and evidence",
			`{"level":"ERROR","msg":"upstream refused","request_body":"{\"name\":\"Acme\"}","response":{"body":"<html>secret page</html>","status":502},"evidence":{"matched":"root:x:0:0"},"headers":{"X-Forwarded-For":"198.51.100.7","Cookie":"sid=abc"}}`,
			[]string{"Acme", "secret page", "root:x:0:0", "198.51.100.7", "sid=abc"},
			[]string{"upstream refused", `"status":502`}},
		{"error text",
			`{"level":"ERROR","msg":"failed to save asset","error":"pq: duplicate key value violates unique constraint \"assets_name_key\" DETAIL: Key (name)=(Payroll Server 01) already exists.","controller":"asset-import","capability":"scan.ports@1"}`,
			[]string{"Payroll Server 01"},
			[]string{"failed to save asset", "assets_name_key", `"controller":"asset-import"`, `"capability":"scan.ports@1"`}},
		{"identifier field with a name in it",
			`{"level":"INFO","msg":"x","tenant_id":"Acme Corp","user_id":"jane@example.com","host_count":4}`,
			[]string{"Acme", "jane"}, []string{`"host_count":4`}},
		{"key carrying a value",
			`{"level":"INFO","msg":"x","per_host":{"scanme.example.com":3}}`,
			[]string{"scanme"}, nil},
		{"compose prefix and logfmt",
			`acme-prod-api-1  | time=2026-11-17T10:00:00Z level=WARN msg="lookup failed" host=db01.corp.example error="dial tcp 192.0.2.9:5432: i/o timeout" attempts=3`,
			[]string{"acme-prod", "db01", "192.0.2.9"},
			[]string{"api-1 | ", `msg="lookup failed"`, "attempts=3", "i/o timeout", "level=WARN"}},
		{"free text line",
			`2026/11/17 10:00:00 http: TLS handshake error from 203.0.113.77:44321: remote error for "portal.example.com"`,
			[]string{"203.0.113.77", "portal.example.com"}, []string{"TLS handshake error"}},
		{"database server statement",
			`postgres-1  | 2026-11-17 10:00:00 UTC [77] LOG:  statement: UPDATE users SET name = 'Jane Doe' WHERE email = 'jane@example.com'`,
			[]string{"Jane Doe", "jane@example.com"}, []string{"statement: UPDATE users SET name ="}},
		{"broken json", `{"level":"INFO","msg":"cut off","email":"jane@example.com`, []string{"jane@"}, nil},
		{"array of hosts", `{"level":"INFO","msg":"resolved","targets":["a.example.com","b.example.com"],"ips":["192.0.2.1"]}`,
			[]string{"a.example.com", "b.example.com", "192.0.2.1"}, []string{"resolved"}},
		{"secret in message", `{"level":"DEBUG","msg":"calling with Authorization: Bearer abcDEF123456ghiJKL7890"}`,
			[]string{"abcDEF123456ghiJKL7890"}, []string{"calling with"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := r.LogLine(tc.in)
			for _, g := range tc.gone {
				if strings.Contains(out, g) {
					t.Errorf("%q survived in %q", g, out)
				}
			}
			for _, k := range tc.kept {
				if !strings.Contains(out, k) {
					t.Errorf("%q lost from %q", k, out)
				}
			}
		})
	}
}

func TestLogLine_TimeAndLength(t *testing.T) {
	r := testRedactor()
	_, at := r.LogLine(`{"time":"2026-11-17T10:00:00.5Z","level":"INFO","msg":"x"}`)
	if at.IsZero() || at.Year() != 2026 {
		t.Fatalf("time = %v", at)
	}
	_, at = r.LogLine(`api-1  | 2026-11-17T09:00:00.000000001Z plain line`)
	if at.Hour() != 9 {
		t.Fatalf("docker time = %v", at)
	}
	_, at = r.LogLine("no time here")
	if !at.IsZero() {
		t.Fatalf("time = %v, want zero", at)
	}
	long, _ := r.LogLine(strings.Repeat("word ", 5000))
	if len(long) > MaxLineBytes+32 {
		t.Fatalf("line of %d bytes not cut", len(long))
	}
}

func TestClassify(t *testing.T) {
	for key, want := range map[string]int{
		"email": classWhole, "userEmail": classWhole, "remote_addr": classWhole, "asset_name": classWhole,
		"request_body": classWhole, "X-Forwarded-For": classText, "user_id": classIdentifier,
		"host_count": classIdentifier, "token_ttl_seconds": classIdentifier, "msg": classText,
		"duration_ms": classText, "status": classText, "": classWhole, "api_key": classWhole,
		"key_id": classIdentifier, "tenantName": classWhole,
	} {
		if got := classify(key); got != want {
			t.Errorf("classify(%q) = %d, want %d", key, got, want)
		}
	}
}
