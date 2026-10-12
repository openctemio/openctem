package bountysource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
)

func TestFetchAPI(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "jdoe" || pass != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/v1/hackers/programs/acme":
			fmt.Fprint(w, `{"data":{"attributes":{"submission_state":"open"}}}`)
		case r.URL.Path == "/v1/hackers/programs/acme/structured_scopes" && r.URL.Query().Get("page[number]") == "1":
			fmt.Fprintf(w, `{"data":[
				{"attributes":{"asset_identifier":"*.acme.example","asset_type":"WILDCARD","eligible_for_submission":true}},
				{"attributes":{"asset_identifier":"com.acme.app","asset_type":"GOOGLE_PLAY_APP_ID","eligible_for_submission":true}}],
				"links":{"next":"%s/v1/hackers/programs/acme/structured_scopes?page%%5Bnumber%%5D=2"}}`, srv.URL)
		case r.URL.Path == "/v1/hackers/programs/acme/structured_scopes":
			fmt.Fprint(w, `{"data":[{"attributes":{"asset_identifier":"admin.acme.example","asset_type":"URL","eligible_for_submission":false}}],"links":{}}`)
		case r.URL.Path == "/v1/hackers/programs/closed":
			fmt.Fprint(w, `{"data":{"attributes":{"submission_state":"disabled"}}}`)
		case r.URL.Path == "/v1/hackers/programs/closed/structured_scopes":
			fmt.Fprint(w, `{"data":[],"links":{}}`)
		case r.URL.Path == "/v1/hackers/programs/evil/structured_scopes":
			fmt.Fprint(w, `{"data":[],"links":{"next":"https://attacker.example/steal"}}`)
		case r.URL.Path == "/v1/hackers/programs/evil":
			fmt.Fprint(w, `{"data":{"attributes":{"submission_state":"open"}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	f := NewWithClient(srv.Client(), srv.URL+"/v1")
	ctx := context.Background()

	items, open, err := f.FetchAPI(ctx, "acme", "jdoe", "tok")
	if err != nil || !open || len(items) != 3 {
		t.Fatalf("acme: %v %v %+v", err, open, items)
	}
	byRaw := map[string]bp.Item{}
	for _, it := range items {
		byRaw[it.Raw] = it
	}
	if w := byRaw["*.acme.example"]; !w.InScope || w.Kind != bp.KindWildcard {
		t.Errorf("wildcard: %+v", w)
	}
	if a := byRaw["com.acme.app"]; a.Scannable() {
		t.Errorf("an app id must not be scannable: %+v", a)
	}
	if o := byRaw["admin.acme.example"]; o.InScope {
		t.Errorf("not eligible for submission is out of scope: %+v", o)
	}

	if _, open, err := f.FetchAPI(ctx, "closed", "jdoe", "tok"); err != nil || open {
		t.Fatalf("closed: %v %v", err, open)
	}
	if _, _, err := f.FetchAPI(ctx, "acme", "jdoe", "wrong"); err == nil || errors.Is(err, ErrGone) {
		t.Fatalf("bad credentials: %v", err)
	}
	if _, _, err := f.FetchAPI(ctx, "nope", "jdoe", "tok"); !errors.Is(err, ErrGone) {
		t.Fatalf("unknown program: %v", err)
	}
	// SECURITY: a next link off the API host is never followed (the
	// credentials would go with it).
	if _, _, err := f.FetchAPI(ctx, "evil", "jdoe", "tok"); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("off-host next link: %v", err)
	}
}

func TestFetchFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scope.txt":
			fmt.Fprint(w, "In scope\n*.acme.example\nOut of scope\nadmin.acme.example\n")
		case "/big.txt":
			fmt.Fprint(w, strings.Repeat("a.acme.example\n", bp.MaxScopeTextBytes/15+10))
		default:
			w.WriteHeader(http.StatusGone)
		}
	}))
	defer srv.Close()
	f := NewWithClient(srv.Client(), "")
	ctx := context.Background()
	items, err := f.FetchFile(ctx, srv.URL+"/scope.txt")
	if err != nil || len(items) != 2 {
		t.Fatalf("file: %v %+v", err, items)
	}
	if _, err := f.FetchFile(ctx, srv.URL+"/big.txt"); !errors.Is(err, bp.ErrScopeTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := f.FetchFile(ctx, srv.URL+"/gone"); !errors.Is(err, ErrGone) {
		t.Fatalf("gone: %v", err)
	}
	// SECURITY: the default client refuses loopback (the outbound guard).
	if _, err := New().FetchFile(ctx, srv.URL+"/scope.txt"); err == nil {
		t.Fatal("the guarded client must refuse a loopback address")
	}
}
