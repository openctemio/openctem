// Package example is a complete extension written only against the public
// extension API (pkg/extension). It is the reference for anyone building
// their own edition and is compiled and tested in every core build, so a
// change that breaks the API breaks this package in the core's own CI.
//
// It adds organization notes: one table in its own schema, a grant key, two
// routes (list and add) gated by a core permission and the grant, a config
// key, and a background controller. A build that wants it passes it to
// server.Main from its own main (api/examples/custombuild does):
//
//	func main() { server.Main(example.Extension()) }
package example

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/extension"
)

// Grant is the grant key of the notes feature.
const Grant limits.GrantKey = "example_notes"

// ConfigGrantAll is the config key that turns the grant on for every
// organization ("true"); otherwise the grant is off.
const ConfigGrantAll = "EXAMPLE_NOTES_GRANT_ALL"

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrations is the example's migration set.
func Migrations() fs.FS {
	m, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		panic(err)
	}
	return m
}

// Extension returns the example's registration.
func Extension() extension.Extension {
	return extension.Extension{
		APIVersion:  1,
		Name:        "example",
		Version:     "v1.0.0",
		Schema:      "example_ext",
		Migrations:  Migrations(),
		ConfigKeys:  []string{ConfigGrantAll},
		Grants:      grants,
		Controllers: controllers,
		Routes:      routes,
	}
}

// provider grants the notes key to every organization when configured.
type provider struct{ all bool }

func (p provider) Grant(_ context.Context, _ shared.ID, k limits.GrantKey) (limits.Grant, error) {
	if p.all && k == Grant {
		return limits.Grant{Key: k, Status: limits.GrantActive}, nil
	}
	return limits.Grant{Key: k, Status: limits.GrantNone}, nil
}

func (provider) Notices(context.Context) ([]limits.Notice, error) { return nil, nil }

func grants(_ context.Context, d extension.Deps) (extension.GrantProvider, error) {
	return provider{all: d.Settings.Get(ConfigGrantAll) == "true"}, nil
}

// Counter is the background controller: it counts the notes of the whole
// installation (an installation-wide read of the extension's own table).
type Counter struct {
	store extension.Store
	last  atomic.Int64
}

// Name implements extension.Controller.
func (*Counter) Name() string { return "example-notes-counter" }

// Interval implements extension.Controller.
func (*Counter) Interval() time.Duration { return time.Hour }

// Exclusive runs it on one replica.
func (*Counter) Exclusive() bool { return true }

// Last is the count of the last run.
func (c *Counter) Last() int64 { return c.last.Load() }

// Reconcile implements extension.Controller.
func (c *Counter) Reconcile(ctx context.Context) (int, error) {
	var n int64
	err := c.store.InstanceTx(ctx, func(ctx context.Context, q extension.Querier) error {
		return q.QueryRowContext(ctx, `SELECT count(*) FROM example_notes`).Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	c.last.Store(n)
	return int(n), nil
}

func controllers(_ context.Context, d extension.Deps) ([]extension.Controller, error) {
	return []extension.Controller{&Counter{store: d.Store}}, nil
}

func routes(_ context.Context, r extension.Router, d extension.Deps) error {
	h := &handler{store: d.Store}
	if err := r.Handle(extension.Route{Method: http.MethodGet, Path: "/example-notes", Permission: "settings:read", Grant: Grant, Handler: http.HandlerFunc(h.list)}); err != nil {
		return err
	}
	return r.Handle(extension.Route{Method: http.MethodPost, Path: "/example-notes", Permission: "settings:write", Grant: Grant, Handler: http.HandlerFunc(h.add)})
}

type handler struct{ store extension.Store }

// Note is one note.
type Note struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	c, ok := extension.CallerFrom(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	notes := []Note{}
	err := h.store.TenantTx(r.Context(), c.TenantID, func(ctx context.Context, q extension.Querier) error {
		rows, err := q.QueryContext(ctx, `SELECT id, body FROM example_notes WHERE tenant_id = $1 ORDER BY id LIMIT 100`, c.TenantID.String())
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var n Note
			if err := rows.Scan(&n.ID, &n.Body); err != nil {
				return err
			}
			notes = append(notes, n)
		}
		return rows.Err()
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": notes})
}

var errBody = errors.New("body must be 1 to 500 characters")

func (h *handler) add(w http.ResponseWriter, r *http.Request) {
	c, ok := extension.CallerFrom(r.Context())
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var in struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || strings.TrimSpace(in.Body) == "" || len(in.Body) > 500 {
		http.Error(w, errBody.Error(), http.StatusBadRequest)
		return
	}
	var n Note
	err := h.store.TenantTx(r.Context(), c.TenantID, func(ctx context.Context, q extension.Querier) error {
		n.Body = in.Body
		return q.QueryRowContext(ctx, `INSERT INTO example_notes (tenant_id, body) VALUES ($1, $2) RETURNING id`, c.TenantID.String(), in.Body).Scan(&n.ID)
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(n)
}
