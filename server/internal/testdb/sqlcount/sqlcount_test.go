package sqlcount

import "testing"

func TestVerb(t *testing.T) {
	cases := map[string]string{
		"SELECT 1":                               "SELECT",
		"  insert into t(a) values ($1)":         "INSERT",
		"\n\tUPDATE t SET a = 1":                 "UPDATE",
		"-- note\nDELETE FROM t":                 "DELETE",
		"/* hint */ WITH x AS (SELECT 1) SELECT": "WITH",
		"COPY t FROM STDIN":                      "COPY",
		"INSERT INTO t(a)VALUES(1)":              "INSERT",
		"":                                       "OTHER",
		"-- only a comment":                      "OTHER",
	}
	for q, want := range cases {
		if got := verb(q); got != want {
			t.Errorf("verb(%q) = %q, want %q", q, got, want)
		}
	}
}

func TestCounterSnapshotIsACopy(t *testing.T) {
	var c Counter
	c.statement("SELECT 1")
	c.statement("select 2")
	c.statement("DELETE FROM t")
	c.tx()
	s := c.Snapshot()
	if s.Statements != 3 || s.Transactions != 1 || s.Verbs["SELECT"] != 2 || s.Verbs["DELETE"] != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
	s.Verbs["SELECT"] = 99
	if c.Snapshot().Verbs["SELECT"] != 2 {
		t.Fatal("the snapshot shares its map with the counter")
	}
	c.Reset()
	if z := c.Snapshot(); z.Statements != 0 || z.Transactions != 0 || len(z.Verbs) != 0 {
		t.Fatalf("reset left %+v", z)
	}
}
