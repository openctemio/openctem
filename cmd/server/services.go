package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/internal/app/pipeline"
	"github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/jobs"
	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/internal/infra/websocket"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/suppression"
	"github.com/openctemio/api/pkg/email"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
)

// wsHubBroadcaster adapts websocket.Hub to app.ActivityBroadcaster and app.TriageBroadcaster interfaces.
type wsHubBroadcaster struct {
	hub *websocket.Hub
}

func (b *wsHubBroadcaster) BroadcastActivity(channel string, data any, tenantID string) {
	b.hub.BroadcastEvent(channel, data, tenantID)
}

func (b *wsHubBroadcaster) BroadcastTriage(channel string, data any, tenantID string) {
	b.hub.BroadcastEvent(channel, data, tenantID)
}

// Services holds all service instances.
type Services struct {
	// Auth
	Auth    *app.AuthService
	Session *app.SessionService

	// Core
	Audit  *app.AuditService
	User   *app.UserService
	Tenant *app.TenantService

	// Assets
	Asset             *app.AssetService
	AssetGroup        *app.AssetGroupService
	AssetType         *app.AssetTypeService
	AssetRelationship *app.AssetRelationshipService
	Scope             *app.ScopeService
	AttackSurface     *app.AttackSurfaceService

	// Configuration (read-only system config)
	FindingSource      *app.FindingSourceService
	FindingSourceCache *app.FindingSourceCacheService

	// Vulnerabilities & Exposures
	Vulnerability    *app.VulnerabilityService
	FindingActivity  *app.FindingActivityService
	Exposure         *app.ExposureService
	ThreatIntel      *app.ThreatIntelService
	CredentialImport *app.CredentialImportService

	// Components & Branches
	Component *app.ComponentService
	Branch    *app.BranchService

	// Dashboard
	Dashboard *app.DashboardService

	// Integrations & Notifications
	Integration  *app.IntegrationService
	Notification *app.NotificationService

	// Agents & Commands
	Agent   *app.AgentService
	Command *app.CommandService
	Ingest  *ingest.Service

	// Scanning & Pipelines
	ScanProfile     *app.ScanProfileService
	ScanSession     *app.ScanSessionService
	Tool            *app.ToolService
	ToolCategory    *app.ToolCategoryService
	Capability      *app.CapabilityService
	Scan            *scan.Service
	Pipeline        *pipeline.Service
	ScannerTemplate *app.ScannerTemplateService
	TemplateSource  *app.TemplateSourceService
	SecretStore     *app.SecretStoreService
	TemplateSyncer  *app.TemplateSyncer

	// Workflows
	Workflow           *app.WorkflowService
	WorkflowDispatcher *app.WorkflowEventDispatcher

	// Suppressions
	Suppression *suppression.Service

	// Agent Selection
	AgentSelector *app.AgentSelector

	// Access Control
	Group      *app.GroupService
	Permission *app.PermissionService
	Role       *app.RoleService

	// Permission Sync
	PermVersion *app.PermissionVersionService
	PermCache   *app.PermissionCacheService

	// Module Cache
	ModuleCache *app.ModuleCacheService

	// Module Service (OSS - all modules enabled)
	Module *app.ModuleService

	// SLA
	SLA *app.SLAService

	// AI Triage
	AITriage *app.AITriageService

	// WebSocket
	WebSocketHub *websocket.Hub

	// Email
	Email        *app.EmailService
	EmailEnqueue app.EmailJobEnqueuer

	// Encryption
	Encryptor crypto.Encryptor

	// JWT
	JWTGenerator *jwt.Generator
}

// ServiceDeps contains dependencies needed to create services.
type ServiceDeps struct {
	Config          *config.Config
	Log             *logger.Logger
	DB              *sql.DB
	Repos           *Repositories
	RedisClient     *redis.Client
	AgentStateStore *redis.AgentStateStore
}

// NewServices initializes all services.
func NewServices(deps *ServiceDeps) (*Services, error) {
	cfg := deps.Config
	log := deps.Log
	repos := deps.Repos

	s := &Services{}

	// Initialize credentials encryptor
	var err error
	s.Encryptor, err = initEncryptor(cfg, log)
	if err != nil {
		return nil, err
	}

	// Initialize audit service first (used by others)
	s.Audit = app.NewAuditService(repos.Audit, log)

	// Initialize core services
	s.User = app.NewUserService(repos.User, log)
	s.Tenant = app.NewTenantService(repos.Tenant, log,
		app.WithTenantAuditService(s.Audit),
	)

	// Initialize asset services
	s.Asset = app.NewAssetService(repos.Asset, log)
	s.Asset.SetRepositoryExtensionRepository(repos.RepoExt)
	s.Asset.SetAssetGroupRepository(repos.AssetGroup)

	s.AssetGroup = app.NewAssetGroupService(repos.AssetGroup, log)
	s.AssetType = app.NewAssetTypeService(repos.AssetType, repos.AssetTypeCat, log)
	s.Scope = app.NewScopeService(repos.ScopeTarget, repos.ScopeExcl, repos.ScopeSchedule, repos.Asset, log)
	s.AttackSurface = app.NewAttackSurfaceService(repos.Asset, log)
	s.AssetRelationship = app.NewAssetRelationshipService(repos.AssetRelationship, repos.Asset, log)

	// Initialize finding source service (read-only system configuration)
	s.FindingSource = app.NewFindingSourceService(repos.FindingSource, repos.FindingSourceCat, log)

	// Initialize finding source cache service (global cache, 24h TTL)
	s.FindingSourceCache, err = app.NewFindingSourceCacheService(deps.RedisClient, repos.FindingSource, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding source cache service: %w", err)
	}

	// Initialize component & branch services
	s.Component = app.NewComponentService(repos.Component, log)
	s.Branch = app.NewBranchService(repos.Branch, log)

	// Initialize vulnerability & exposure services
	s.Vulnerability = app.NewVulnerabilityService(repos.Vulnerability, repos.Finding, log)
	s.Vulnerability.SetCommentRepository(repos.FindingComment)
	s.Vulnerability.SetDataFlowRepository(repos.DataFlow) // Wire data flow loading
	s.FindingActivity = app.NewFindingActivityService(repos.FindingActivity, repos.Finding, log)
	s.FindingActivity.SetUserRepo(repos.User) // Wire user lookup for activity broadcasts
	// Note: WebSocket broadcaster is wired later after WebSocketHub is initialized

	// Wire activity service dependencies
	s.Vulnerability.SetActivityService(s.FindingActivity) // Wire activity tracking
	s.Vulnerability.SetUserRepository(repos.User)         // Wire user lookup for activity records

	s.Exposure = app.NewExposureService(repos.Exposure, repos.ExposureStateHistory, log)
	s.ThreatIntel = app.NewThreatIntelService(repos.ThreatIntel, log)
	s.CredentialImport = app.NewCredentialImportService(repos.Exposure, repos.ExposureStateHistory, log)

	// Initialize dashboard service
	s.Dashboard = app.NewDashboardService(repos.Dashboard, log)

	// Initialize SLA service
	s.SLA = app.NewSLAService(repos.SLA, log)

	// Initialize integration & notification services
	s.Integration = app.NewIntegrationService(repos.Integration, repos.IntegrationSCMExt, s.Encryptor, log)
	s.Integration.SetNotificationExtensionRepository(repos.IntegrationNotificationExt)
	s.Integration.SetNotificationEventRepository(repos.NotificationEvent)

	s.Notification = app.NewNotificationService(
		repos.NotificationOutbox,
		repos.NotificationEvent,
		repos.IntegrationNotificationExt,
		s.Encryptor.DecryptString,
		log.Logger,
	)

	// Wire notification to vulnerability and exposure services
	s.Vulnerability.SetNotificationService(deps.DB, s.Notification)
	s.Exposure.SetNotificationService(deps.DB, s.Notification)

	// Initialize agent & command services
	s.Agent = app.NewAgentService(repos.Agent, s.Audit, log)
	s.Command = app.NewCommandService(repos.Command, log)

	// Initialize ingest service (unified ingestion engine)
	s.Ingest = ingest.NewService(repos.Asset, repos.Finding, repos.Component, repos.Agent, repos.Branch, repos.Tenant, repos.Audit, log)
	s.Ingest.SetDataFlowRepository(repos.DataFlow)           // Wire data flow persistence
	s.Ingest.SetComponentRepository(repos.Component)         // Wire component linking for SCA findings
	s.Ingest.SetRepositoryExtensionRepository(repos.RepoExt) // Wire repository extension for auto web_url

	// Initialize scanning services
	s.ScanProfile = app.NewScanProfileService(repos.ScanProfile, log)
	s.ScanSession = app.NewScanSessionService(repos.ScanSession, repos.Agent, log)
	s.ScannerTemplate = app.NewScannerTemplateService(repos.ScannerTemplate, cfg.Encryption.Key, log)
	s.TemplateSource = app.NewTemplateSourceService(repos.TemplateSource, log)

	// Initialize credential service for template sources
	// Decode hex key to bytes (64 hex chars -> 32 bytes for AES-256)
	encryptionKey, err := hex.DecodeString(cfg.Encryption.Key)
	if err != nil {
		// Fallback to raw bytes if not hex encoded
		encryptionKey = []byte(cfg.Encryption.Key)
	}
	s.SecretStore, err = app.NewSecretStoreService(repos.SecretStore, encryptionKey, s.Audit, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secret store service: %w", err)
	}

	// Initialize template syncer for fetching templates from external sources
	s.TemplateSyncer = app.NewTemplateSyncer(
		repos.TemplateSource,
		repos.ScannerTemplate,
		s.SecretStore,
		encryptionKey,
		log,
	)

	// Wire up template syncer to source service for force sync API
	s.TemplateSource.SetTemplateSyncer(s.TemplateSyncer)

	s.Tool = app.NewToolService(repos.Tool, repos.TenantToolConfig, repos.ToolExecution, log)
	s.Tool.SetAgentRepo(repos.Agent)           // Enable tool availability checking
	s.Tool.SetCategoryRepo(repos.ToolCategory) // Enable category info in responses
	s.ToolCategory = app.NewToolCategoryService(repos.ToolCategory, log)
	s.Capability = app.NewCapabilityService(repos.Capability, s.Audit, log)

	// Initialize agent selector for load balancing
	s.AgentSelector = app.NewAgentSelector(repos.Agent, repos.Command, deps.AgentStateStore, log)

	// Initialize security validator for pipeline/scan operations
	securityValidator := app.NewSecurityValidator(repos.Tool, log)

	// Create adapters for scan sub-package (clean architecture - each package defines its own interfaces)
	scanAuditAdapter := app.NewScanAuditServiceAdapter(s.Audit)
	scanAgentSelectorAdapter := app.NewScanAgentSelectorAdapter(s.AgentSelector)
	scanTemplateSyncerAdapter := app.NewScanTemplateSyncerAdapter(s.TemplateSyncer)
	scanSecurityValidatorAdapter := app.NewScanSecurityValidatorAdapter(securityValidator)

	// Initialize scan service with adapters for its interfaces
	s.Scan = scan.NewService(
		repos.Scan,
		repos.PipelineTemplate,
		repos.AssetGroup,
		repos.PipelineRun,
		repos.PipelineStep,
		repos.StepRun,
		repos.Command,
		repos.ScannerTemplate,
		repos.TemplateSource,
		repos.Tool,
		scanTemplateSyncerAdapter,
		scanAgentSelectorAdapter,
		scanSecurityValidatorAdapter,
		log,
		scan.WithAuditService(scanAuditAdapter),
	)

	// Create adapters for pipeline sub-package
	pipelineAuditAdapter := app.NewPipelineAuditServiceAdapter(s.Audit)
	pipelineAgentSelectorAdapter := app.NewPipelineAgentSelectorAdapter(s.AgentSelector)
	pipelineSecurityValidatorAdapter := app.NewPipelineSecurityValidatorAdapter(securityValidator)

	// Initialize pipeline service with security validator, audit service, transaction support, and tool repo
	s.Pipeline = pipeline.NewService(
		repos.PipelineTemplate,
		repos.PipelineStep,
		repos.PipelineRun,
		repos.StepRun,
		repos.Agent,
		repos.Command,
		pipelineSecurityValidatorAdapter,
		log,
		pipeline.WithAuditService(pipelineAuditAdapter),
		pipeline.WithDB(deps.DB),
		pipeline.WithAgentSelector(pipelineAgentSelectorAdapter),
		pipeline.WithToolRepo(repos.Tool),
		pipeline.WithQualityGate(repos.ScanProfile, repos.Finding),
		pipeline.WithScanDeactivator(s.Scan), // Cascade pause scans when pipeline is deactivated
	)

	// Wire up pipeline deactivator to tool service for cascade deactivation
	// When a tool is deactivated/deleted, all active pipelines using it will be deactivated
	s.Tool.SetPipelineDeactivator(s.Pipeline)

	// Initialize workflow executor
	workflowExecutor := app.NewWorkflowExecutor(
		repos.Workflow,
		repos.WorkflowRun,
		repos.WorkflowNodeRun,
		log,
		app.WithExecutorDB(deps.DB),
		app.WithExecutorNotificationService(s.Notification),
		app.WithExecutorIntegrationService(s.Integration),
		app.WithExecutorAuditService(s.Audit),
	)

	// Register all action handlers for the workflow executor
	app.RegisterAllActionHandlers(
		workflowExecutor,
		s.Vulnerability,
		s.Pipeline,
		s.Scan,
		s.Integration,
		log,
	)

	// Initialize workflow service with executor
	s.Workflow = app.NewWorkflowService(
		repos.Workflow,
		repos.WorkflowNode,
		repos.WorkflowEdge,
		repos.WorkflowRun,
		repos.WorkflowNodeRun,
		log,
		app.WithWorkflowAuditService(s.Audit),
		app.WithWorkflowExecutor(workflowExecutor),
	)

	// Initialize workflow event dispatcher for automatic workflow triggering
	s.WorkflowDispatcher = app.NewWorkflowEventDispatcher(
		repos.Workflow,
		repos.WorkflowNode,
		s.Workflow,
		log,
	)

	// Wire workflow dispatcher to ingest service for automatic workflow triggering
	// when new findings are created during ingestion
	s.Ingest.SetFindingCreatedCallback(s.WorkflowDispatcher.DispatchFindingsCreated)

	// Initialize suppression service (platform-controlled false positive management)
	s.Suppression = suppression.NewService(repos.Suppression, log)

	// Initialize access control services
	s.Group = app.NewGroupService(repos.Group, log,
		app.WithGroupAuditService(s.Audit),
		app.WithPermissionSetRepository(repos.PermissionSet),
		app.WithAccessControlRepository(repos.AccessControl),
	)

	s.Permission = app.NewPermissionService(repos.PermissionSet, log,
		app.WithPermissionAuditService(s.Audit),
		app.WithPermissionAccessControlRepository(repos.AccessControl),
		app.WithPermissionGroupRepository(repos.Group),
	)

	// Initialize permission sync services
	s.PermVersion = app.NewPermissionVersionService(deps.RedisClient, log)
	s.PermCache, err = app.NewPermissionCacheService(deps.RedisClient, repos.Role, s.PermVersion, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize permission cache service: %w", err)
	}

	s.Role = app.NewRoleService(repos.Role, repos.RolePermission, log,
		app.WithRoleAuditService(s.Audit),
		app.WithRolePermissionVersionService(s.PermVersion),
		app.WithRolePermissionCacheService(s.PermCache),
	)

	// Wire permission services to tenant service
	s.Tenant.SetPermissionServices(s.PermCache, s.PermVersion)

	// Initialize licensing service (OSS edition - modules from database)
	s.Module = app.NewModuleService(repos.Module, log)

	// Initialize WebSocket hub for real-time features
	s.WebSocketHub = websocket.NewHub(log)
	log.Info("websocket hub initialized")

	// Wire WebSocket broadcasters - must be done AFTER WebSocketHub is initialized
	broadcaster := &wsHubBroadcaster{hub: s.WebSocketHub}

	// Wire to FindingActivity for real-time activity updates on finding:* channels
	if s.FindingActivity != nil {
		s.FindingActivity.SetBroadcaster(broadcaster)
		log.Info("FindingActivity broadcaster wired to WebSocket hub")
	}

	// Wire to AI Triage for real-time triage updates on triage:* channels
	if s.AITriage != nil {
		s.AITriage.SetTriageBroadcaster(broadcaster)
		log.Info("AI triage broadcaster wired to WebSocket hub")
	}

	return s, nil
}

// InitAuthServices initializes authentication-related services.
// Should be called only if local auth is supported.
func (s *Services) InitAuthServices(cfg *config.Config, repos *Repositories, log *logger.Logger) {
	// Initialize JWT generator
	s.JWTGenerator = jwt.NewGenerator(jwt.TokenConfig{
		Secret:               cfg.Auth.JWTSecret,
		Issuer:               cfg.Auth.JWTIssuer,
		AccessTokenDuration:  cfg.Auth.AccessTokenDuration,
		RefreshTokenDuration: cfg.Auth.RefreshTokenDuration,
	})

	// Initialize session service
	s.Session = app.NewSessionService(repos.Session, repos.RefreshToken, log)

	// Initialize auth service
	s.Auth = app.NewAuthService(repos.User, repos.Session, repos.RefreshToken, repos.Tenant, s.Audit, cfg.Auth, log)
	s.Auth.SetRoleService(s.Role)

	// Wire permission services to session service
	tenantMembershipAdapter := app.NewTenantMembershipAdapter(repos.Tenant)
	s.Session.SetPermissionServices(s.PermCache, s.PermVersion, tenantMembershipAdapter)

	// Wire session service to user service for session revocation on suspension
	s.User.SetSessionService(s.Session)
}

// InitEmailServices initializes email-related services.
func (s *Services) InitEmailServices(cfg *config.Config, log *logger.Logger) error {
	if !cfg.SMTP.IsConfigured() {
		log.Warn("email service not configured - email features will be disabled")
		return nil
	}

	emailSender := email.NewSMTPSender(email.Config{
		Host:       cfg.SMTP.Host,
		Port:       cfg.SMTP.Port,
		User:       cfg.SMTP.User,
		Password:   cfg.SMTP.Password,
		From:       cfg.SMTP.From,
		FromName:   cfg.SMTP.FromName,
		TLS:        cfg.SMTP.TLS,
		SkipVerify: cfg.SMTP.SkipVerify,
		Timeout:    cfg.SMTP.Timeout,
	})
	s.Email = app.NewEmailService(emailSender, cfg.SMTP, cfg.App.Name, log)
	log.Info("email service initialized", "host", cfg.SMTP.Host, "from", cfg.SMTP.From)

	return nil
}

// SetEmailEnqueuer sets the email job enqueuer.
func (s *Services) SetEmailEnqueuer(enqueuer app.EmailJobEnqueuer) {
	s.EmailEnqueue = enqueuer
	s.Tenant = app.NewTenantService(nil, nil, app.WithEmailEnqueuer(enqueuer))
}

// initEncryptor initializes the credentials encryptor.
func initEncryptor(cfg *config.Config, log *logger.Logger) (crypto.Encryptor, error) {
	if !cfg.Encryption.IsConfigured() {
		log.Warn("APP_ENCRYPTION_KEY not configured - credentials will be stored in plaintext")
		return crypto.NewNoOpEncryptor(), nil
	}

	var encryptor crypto.Encryptor
	var err error

	switch cfg.Encryption.KeyFormat {
	case "hex":
		encryptor, err = crypto.NewCipherFromHex(cfg.Encryption.Key)
	case "base64":
		encryptor, err = crypto.NewCipherFromBase64(cfg.Encryption.Key)
	default:
		encryptor, err = crypto.NewCipher([]byte(cfg.Encryption.Key))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize credentials encryptor: %w", err)
	}

	log.Info("credentials encryption enabled")
	return encryptor, nil
}

// NewJobClient creates a new job client for background processing.
func NewJobClient(cfg *config.Config, log *logger.Logger) (*jobs.Client, error) {
	redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
	jobClientCfg := jobs.ClientConfig{
		RedisAddr:     redisAddr,
		RedisPassword: cfg.Redis.Password,
		RedisDB:       cfg.Redis.DB,
	}

	client, err := jobs.NewClient(jobClientCfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize job client: %w", err)
	}

	log.Info("job client initialized", "redis_addr", redisAddr)
	return client, nil
}

// NewJobWorker creates a new job worker for processing background jobs.
func NewJobWorker(cfg *config.Config, emailService *app.EmailService, aiTriageService *app.AITriageService, log *logger.Logger) (*jobs.Worker, error) {
	if emailService == nil {
		return nil, nil
	}

	redisAddr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
	workerCfg := jobs.WorkerConfig{
		RedisAddr:     redisAddr,
		RedisPassword: cfg.Redis.Password,
		RedisDB:       cfg.Redis.DB,
		Concurrency:   5,
	}

	// Build worker options
	var opts []jobs.WorkerOption
	if aiTriageService != nil {
		opts = append(opts, jobs.WithAITriageProcessor(aiTriageService))
	}

	worker, err := jobs.NewWorker(workerCfg, emailService, log, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize job worker: %w", err)
	}

	log.Info("job worker initialized")
	return worker, nil
}
