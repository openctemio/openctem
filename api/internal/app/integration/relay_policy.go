package integration

// A tenant e-mail channel whose relay no longer meets the managed service
// rules (pkg/email ValidateTenantRelay) is stopped with a visible status, and
// the organization's owners are told once. It is never dropped silently:
// the integration shows INTEGRATION_EMAIL_RELAY_POLICY until an admin edits
// the relay and tests it again.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/apierror"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
)

// RelayOwners lists an organization's active owners.
type RelayOwners interface {
	ListActiveOwners(ctx context.Context, tenantID shared.ID) ([]ssochange.OwnerContact, error)
}

// RelayInAppNotifier raises an in-app notification.
type RelayInAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// RelayMailer e-mails an owner through the platform's own relay.
type RelayMailer interface {
	NotifyEmailRelayStopped(ctx context.Context, ownerEmail, ownerName, subject, message string)
}

// SetRelayPolicyNotices wires the in-app owner notices of a stopped relay.
func (s *IntegrationService) SetRelayPolicyNotices(owners RelayOwners, inApp *NotificationService) {
	s.relayOwners = owners
	if inApp != nil {
		s.relayInApp = inApp
	}
}

// SetRelayPolicyMailer also e-mails the owners (the platform's own relay).
func (s *IntegrationService) SetRelayPolicyMailer(m RelayMailer) { s.relayMailer = m }

// EmailRelayRefused is called when a delivery through an e-mail integration
// was refused by the managed service rules. It marks the integration as
// failed with the policy code (so the channel stops and the console shows
// why) and tells the owners. It acts once per episode: an integration that
// already shows the code is left alone.
func (s *IntegrationService) EmailRelayRefused(ctx context.Context, tenantID, integrationID shared.ID, cause error) {
	intg, err := s.repo.GetByID(ctx, integrationID)
	if err != nil || intg.TenantID() != tenantID {
		return
	}
	if intg.Status() == integrationdom.StatusError && intg.StatusCode() == string(apierror.CodeIntegrationEmailRelayPolicy) {
		return
	}
	f := ClassifyConnFailure(cause)
	s.logger.Warn("e-mail channel stopped by the managed service rules",
		"tenant_id", tenantID.String(), "integration_id", integrationID.String(), "error", cause)
	intg.SetFailure(string(f.Code), f.Message)
	if err := s.repo.Update(ctx, intg); err != nil {
		s.logger.Error("record stopped e-mail channel", "integration_id", integrationID.String(), "error", err)
		return
	}
	s.notifyOwnersRelayStopped(ctx, intg)
}

func (s *IntegrationService) notifyOwnersRelayStopped(ctx context.Context, intg *integrationdom.Integration) {
	if s.relayOwners == nil {
		return
	}
	owners, err := s.relayOwners.ListActiveOwners(ctx, intg.TenantID())
	if err != nil {
		s.logger.Error("list owners for stopped e-mail channel", "tenant_id", intg.TenantID().String(), "error", err)
		return
	}
	title := "An e-mail channel was stopped"
	body := fmt.Sprintf("The e-mail channel %q no longer meets the service rules for mail servers: "+
		"use port 465, 587 or 2525 with a username, a password and TLS. Notifications through it are stopped. "+
		"Edit the channel under Settings > Integrations > Notifications and test it to resume.", intg.Name())
	integrationID := intg.ID()
	for _, o := range owners {
		uid := o.UserID
		if s.relayInApp != nil {
			if err := s.relayInApp.Notify(ctx, notificationdom.NotificationParams{
				TenantID:         intg.TenantID(),
				Audience:         notificationdom.AudienceUser,
				AudienceID:       &uid,
				NotificationType: notificationdom.TypeSystemAlert,
				Title:            title,
				Body:             body,
				Severity:         notificationdom.SeverityHigh,
				ResourceType:     "integration",
				ResourceID:       &integrationID,
				URL:              "/settings/integrations/notifications",
			}); err != nil {
				s.logger.Error("notify owner of stopped e-mail channel", "tenant_id", intg.TenantID().String(), "error", err)
			}
		}
		if s.relayMailer != nil && o.Email != "" {
			s.relayMailer.NotifyEmailRelayStopped(ctx, o.Email, o.Name, title, body)
		}
	}
}
