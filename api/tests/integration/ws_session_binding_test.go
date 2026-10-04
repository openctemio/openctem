package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	gws "github.com/gorilla/websocket"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Session-bound sockets end to end (RFC-045): the real logout, member
// suspension, removal and role-change paths close a live socket — on another
// API instance, through the Redis revocation channel.
//
// Two hubs stand for two API instances, each with its own Redis bridge on
// per-test channels. The services run on instance A; every socket is opened
// on instance B. Needs DATABASE_URL and REDIS_HOST (CI sets both).

type wsBindingFixture struct {
	*revFixture
	sessions  *authapp.SessionService
	auth      *authapp.AuthService
	sessRepo  *postgres.SessionRepository
	instanceB *httptest.Server
}

func newWSBindingFixture(t *testing.T) *wsBindingFixture {
	t.Helper()
	f := newRevFixture(t) // skips without DATABASE_URL / REDIS_HOST
	log := logger.NewNop()

	port := 6379
	if p := os.Getenv("REDIS_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("REDIS_PORT: %v", err)
		}
		port = n
	}
	rc, err := redis.New(&config.RedisConfig{
		Host: os.Getenv("REDIS_HOST"), Port: port, PoolSize: 4,
		DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
		MaxRetries: 1, MinRetryDelay: 10 * time.Millisecond, MaxRetryDelay: 50 * time.Millisecond,
	}, log)
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	suffix := uuid.NewString()
	bridgeCfg := func() *websocket.BridgeConfig {
		return &websocket.BridgeConfig{Channel: "ws:broadcast:it-" + suffix, RevokeChannel: "ws:revoke:it-" + suffix, Logger: log}
	}
	hubA, hubB := websocket.NewHub(log), websocket.NewHub(log)
	for _, h := range []*websocket.Hub{hubA, hubB} {
		go h.Run(ctx)
		b := websocket.NewRedisBridge(rc.Client(), h, bridgeCfg())
		go func() { _ = b.Start(ctx) }()
	}
	// Both bridges must be subscribed before anything is published.
	deadline := time.Now().Add(5 * time.Second)
	for {
		n, err := rc.Client().PubSubNumSub(ctx, "ws:revoke:it-"+suffix).Result()
		if err == nil && n["ws:revoke:it-"+suffix] == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridges did not subscribe: %v %v", n, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Instance A: the services, wired as cmd/server wires them.
	tokens, err := redis.NewTokenStore(rc, log)
	if err != nil {
		t.Fatal(err)
	}
	store, err := redis.NewSessionRevocationStore(tokens)
	if err != nil {
		t.Fatal(err)
	}
	notifier := websocket.SessionRevocationNotifier{Store: store, Hub: hubA}
	f.permVersion.SetChangeListener(func(ctx context.Context, tenantID, userID string) {
		hubA.RevokeAccess(ctx, tenantID, userID)
	})

	sessRepo := postgres.NewSessionRepository(f.db)
	rtRepo := postgres.NewRefreshTokenRepository(f.db)
	pg := &postgres.DB{DB: f.db}
	sessions := authapp.NewSessionService(sessRepo, rtRepo, log)
	sessions.SetRevocationStore(notifier, time.Hour)
	f.tenantSvc.SetSessionService(sessions)
	auth := authapp.NewAuthService(postgres.NewUserRepository(pg), sessRepo, rtRepo, f.tenants,
		auditapp.NewAuditService(postgres.NewAuditRepository(pg), log), config.AuthConfig{AccessTokenDuration: 15 * time.Minute}, log)
	auth.SetSessionRevocationStore(notifier)

	// Instance B: serves the sockets. The stand-in for the auth middleware
	// puts the identity from the query into the context.
	wsB := websocket.NewHandler(hubB, log, nil, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c := context.WithValue(r.Context(), middleware.UserIDKey, q.Get("user"))
		c = context.WithValue(c, middleware.TenantIDKey, q.Get("tenant"))
		c = context.WithValue(c, middleware.SessionIDKey, q.Get("session"))
		c = context.WithValue(c, middleware.CredentialExpiresAtKey, time.Now().Add(time.Hour))
		wsB.ServeWS(w, r.WithContext(c))
	}))
	t.Cleanup(srv.Close)

	return &wsBindingFixture{revFixture: f, sessions: sessions, auth: auth, sessRepo: sessRepo, instanceB: srv}
}

// session creates an active session row for uid.
func (f *wsBindingFixture) session(uid string) string {
	f.t.Helper()
	u, _ := shared.IDFromString(uid)
	s, err := sessiondom.New(u, "tok-"+uuid.NewString(), "127.0.0.1", "ws-it", time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.sessRepo.Create(f.ctx, s); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM sessions WHERE id = $1`, s.ID().String())
	})
	return s.ID().String()
}

// open connects to instance B as uid/session in the fixture tenant and proves
// the socket works.
func (f *wsBindingFixture) open(uid, sessionID string) *gws.Conn {
	f.t.Helper()
	u := "ws" + strings.TrimPrefix(f.instanceB.URL, "http") + "/?user=" + uid + "&tenant=" + f.tenantID + "&session=" + sessionID
	conn, resp, err := gws.DefaultDialer.Dial(u, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		f.t.Fatalf("dial: %v", err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	if !wsAlive(conn) {
		f.t.Fatal("new socket does not answer")
	}
	return conn
}

func wsAlive(conn *gws.Conn) bool {
	if err := conn.WriteJSON(websocket.Message{Type: websocket.MessageTypePing}); err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var m websocket.Message
		if err := conn.ReadJSON(&m); err != nil {
			return false
		}
		if m.Type == websocket.MessageTypePong {
			return true
		}
	}
}

// wsCloseCode waits for the server to close the socket and returns the code.
func wsCloseCode(t *testing.T, conn *gws.Conn) int {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			var ce *gws.CloseError
			if errors.As(err, &ce) {
				return ce.Code
			}
			t.Fatalf("socket ended without a close frame: %v", err)
		}
	}
}

func TestWSBinding_LogoutClosesTheSessionSocketOnAnotherInstance(t *testing.T) {
	f := newWSBindingFixture(t)
	u := f.member("member", false)
	loggedOut, otherDevice := f.session(u), f.session(u)
	conn := f.open(u, loggedOut)
	keep := f.open(u, otherDevice)

	if err := f.auth.Logout(f.ctx, loggedOut); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if code := wsCloseCode(t, conn); code != websocket.CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, websocket.CloseUnauthorized)
	}
	if !wsAlive(keep) {
		t.Fatal("the socket of the user's other session was closed")
	}
}

func TestWSBinding_SuspendedMemberSocketCloses(t *testing.T) {
	f := newWSBindingFixture(t)
	owner := f.member("owner", false)
	u := f.member("member", false)
	conn := f.open(u, f.session(u))
	bystander := f.member("member", false)
	keep := f.open(bystander, f.session(bystander))

	if err := f.tenantSvc.SuspendMember(f.ctx, f.membershipID(u),
		auditapp.AuditContext{TenantID: f.tenantID, ActorID: owner}); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	if code := wsCloseCode(t, conn); code != websocket.CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, websocket.CloseUnauthorized)
	}
	if !wsAlive(keep) {
		t.Fatal("another member's socket was closed")
	}
}

func TestWSBinding_RemovedMemberSocketCloses(t *testing.T) {
	f := newWSBindingFixture(t)
	owner := f.member("owner", false)
	u := f.member("member", false)
	conn := f.open(u, f.session(u))

	if err := f.tenantSvc.RemoveMember(f.ctx, f.membershipID(u),
		auditapp.AuditContext{TenantID: f.tenantID, ActorID: owner}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if code := wsCloseCode(t, conn); code != websocket.CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, websocket.CloseUnauthorized)
	}
}

func TestWSBinding_RoleChangeClosesSocket(t *testing.T) {
	f := newWSBindingFixture(t)
	owner := f.member("owner", false)
	admin := f.member("admin", false)
	conn := f.open(admin, f.session(admin))

	if _, err := f.tenantSvc.UpdateMemberRole(f.ctx, f.membershipID(admin), tenantapp.UpdateMemberRoleInput{Role: "viewer"},
		auditapp.AuditContext{TenantID: f.tenantID, ActorID: owner}); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if code := wsCloseCode(t, conn); code != websocket.CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, websocket.CloseUnauthorized)
	}
}
