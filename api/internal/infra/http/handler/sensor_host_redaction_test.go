package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

func TestRedactSensorHost_AdminOnly(t *testing.T) {
	ip := "10.0.0.7"
	mk := func() *SensorResponse {
		return &SensorResponse{Hostname: "build-01", IPAddress: "10.0.0.5", KeyLastUsedIP: &ip, Name: "s"}
	}
	member := redactSensorHost(context.Background(), mk())
	if member.Hostname != "" || member.IPAddress != "" || member.KeyLastUsedIP != nil || member.Name != "s" {
		t.Errorf("non-admin sees host details: %+v", member)
	}
	admin := redactSensorHost(context.WithValue(context.Background(), middleware.IsAdminKey, true), mk())
	if admin.Hostname == "" || admin.IPAddress == "" || admin.KeyLastUsedIP == nil {
		t.Errorf("admin lost host details: %+v", admin)
	}
}
