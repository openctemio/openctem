package app

// Compatibility shim — real impl lives in internal/app/integration/.
// Covers integration + notification + webhook + attachment +
// credential_import + secretstore (all bounded by "external integrations").

import "github.com/openctemio/api/internal/app/integration"

type (
	IntegrationService                 = integration.IntegrationService
	NotificationService                = integration.NotificationService
	WebhookService                     = integration.WebhookService
	AttachmentService                  = integration.AttachmentService
	CredentialImportService            = integration.CredentialImportService
	SecretStoreService                 = integration.SecretStoreService
	BroadcastNotificationInput         = integration.BroadcastNotificationInput
	CreateCredentialInput              = integration.CreateCredentialInput
	CreateIntegrationInput             = integration.CreateIntegrationInput
	CreateNotificationIntegrationInput = integration.CreateNotificationIntegrationInput
	CreateWebhookInput                 = integration.CreateWebhookInput
	CredentialItem                     = integration.CredentialItem
	CredentialListOptions              = integration.CredentialListOptions
	CredentialListResult               = integration.CredentialListResult
	EmailCredentials                   = integration.EmailCredentials
	EmailMetadata                      = integration.EmailMetadata
	EmailSensitiveCredentials          = integration.EmailSensitiveCredentials
	FindSCMIntegrationInput            = integration.FindSCMIntegrationInput
	GetNotificationEventsInput         = integration.GetNotificationEventsInput
	GetNotificationEventsResult        = integration.GetNotificationEventsResult
	GetSCMRepositoryInput              = integration.GetSCMRepositoryInput
	IdentityExposure                   = integration.IdentityExposure
	IdentityListResult                 = integration.IdentityListResult
	IntegrationListReposInput          = integration.IntegrationListReposInput
	IntegrationListReposResult         = integration.IntegrationListReposResult
	ListCredentialsInput               = integration.ListCredentialsInput
	ListCredentialsOutput              = integration.ListCredentialsOutput
	ListDeliveriesInput                = integration.ListDeliveriesInput
	ListIntegrationsInput              = integration.ListIntegrationsInput
	ListWebhooksInput                  = integration.ListWebhooksInput
	NotificationEventEntry             = integration.NotificationEventEntry
	NotificationEventSendResult        = integration.NotificationEventSendResult
	SendNotificationInput              = integration.SendNotificationInput
	SendNotificationResult             = integration.SendNotificationResult
	StorageFactory                     = integration.StorageFactory
	TelegramCredentials                = integration.TelegramCredentials
	TenantStorageResolver              = integration.TenantStorageResolver
	TestIntegrationCredentialsInput    = integration.TestIntegrationCredentialsInput
	TestIntegrationCredentialsResult   = integration.TestIntegrationCredentialsResult
	UpdateCredentialInput              = integration.UpdateCredentialInput
	UpdateIntegrationInput             = integration.UpdateIntegrationInput
	UpdateNotificationIntegrationInput = integration.UpdateNotificationIntegrationInput
	UpdatePreferencesInput             = integration.UpdatePreferencesInput
	UpdateWebhookInput                 = integration.UpdateWebhookInput
	UploadInput                        = integration.UploadInput
	WebSocketBroadcaster               = integration.WebSocketBroadcaster
)

var (
	NewAttachmentService       = integration.NewAttachmentService
	NewCredentialImportService = integration.NewCredentialImportService
	NewIntegrationService      = integration.NewIntegrationService
	NewNotificationService     = integration.NewNotificationService
	NewSecretStoreService      = integration.NewSecretStoreService
	NewWebhookService          = integration.NewWebhookService
)
