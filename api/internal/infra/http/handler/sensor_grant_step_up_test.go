package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

type fixedRecentAuth struct {
	at  time.Time
	err error
}

func (f fixedRecentAuth) RecentAuthAt(context.Context, string, string) (time.Time, error) {
	return f.at, f.err
}

func TestStepUpWideningApprover(t *testing.T) {
	const window = 10 * time.Minute
	session := func() context.Context {
		ctx := context.WithValue(context.Background(), middleware.UserIDKey, "u1")
		return context.WithValue(ctx, middleware.SessionIDKey, "s1")
	}
	cases := []struct {
		name    string
		ctx     context.Context
		checker middleware.RecentAuthChecker
		want    error
	}{
		{"recent sign-in widens", session(), fixedRecentAuth{at: time.Now().Add(-time.Minute)}, nil},
		{"stale session needs step-up", session(), fixedRecentAuth{at: time.Now().Add(-window - time.Second)}, middleware.ErrStepUpRequired},
		{"unknown session needs step-up", session(), fixedRecentAuth{err: middleware.ErrNoRecentAuth}, middleware.ErrStepUpRequired},
		{"no user session cannot step up", context.Background(), fixedRecentAuth{at: time.Now()}, middleware.ErrStepUpUnavailable},
		{"no checker cannot step up", session(), nil, middleware.ErrStepUpUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := StepUpWideningApprover{Checker: tc.checker, Window: window}
			err := a.ApproveWidening(tc.ctx, sensorgrant.Actor{}, sensordom.Grant{}, sensordom.Grant{}, []string{"trust_level"})
			if !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("lookup failure fails closed", func(t *testing.T) {
		boom := errors.New("db down")
		a := StepUpWideningApprover{Checker: fixedRecentAuth{err: boom}, Window: window}
		if err := a.ApproveWidening(session(), sensorgrant.Actor{}, sensordom.Grant{}, sensordom.Grant{}, nil); !errors.Is(err, boom) {
			t.Fatalf("got %v, want the lookup error", err)
		}
	})
}

func TestWriteGrantErrorStepUp(t *testing.T) {
	h := &SensorHandler{}
	for err, code := range map[error]string{
		middleware.ErrStepUpRequired:    string(middleware.CodeStepUpRequired),
		middleware.ErrStepUpUnavailable: string(middleware.CodeStepUpUnavailable),
	} {
		rec := httptest.NewRecorder()
		h.writeGrantError(rec, err)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%v: status %d, want 403", err, rec.Code)
		}
		var body struct {
			Code string `json:"code"`
		}
		if e := json.Unmarshal(rec.Body.Bytes(), &body); e != nil || body.Code != code {
			t.Fatalf("%v: body %s, want code %s", err, rec.Body.String(), code)
		}
	}
}
