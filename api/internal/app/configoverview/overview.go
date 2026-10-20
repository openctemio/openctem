// Package configoverview lists the installation's operator settings for the
// platform console's Configuration page: for each one, whether it is managed
// in the console or on the server, where the effective value comes from
// (console, environment or built-in default), whether changing it needs a
// restart, and which console page changes it.
//
// It never returns a secret: a secret appears only as set or not set.
// Values of settings the console manages are shown on their own pages; the
// overview gives their source and who last changed them.
//
// Design: docs/rfcs/RFC-022-platform-admin-console.md (revision 22).
package configoverview

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Where a setting is managed.
const (
	ManagedConsole = "console"
	ManagedServer  = "server"
)

// Where an effective value comes from.
const (
	SourceConsole     = "console"
	SourceEnvironment = "environment"
	SourceDefault     = "default"
)

// Groups, in page order.
const (
	GroupInstance = "instance"
	GroupSignIn   = "sign_in"
	GroupEmail    = "email"
	GroupScanning = "scanning"
	GroupStorage  = "storage"
	GroupAI       = "ai"
	GroupConsole  = "console"
	GroupAudit    = "audit"
	GroupUpdates  = "updates"
	GroupAlerts   = "alerts"
)

// Item is one row of the Configuration page.
type Item struct {
	// Key is stable: a platform setting key or an environment variable name.
	Key   string `json:"key"`
	Group string `json:"group"`
	// Managed: console (changed on a console page, applied without a restart)
	// or server (environment or installer, needs a restart).
	Managed string `json:"managed"`
	Source  string `json:"source"`
	// Value is a display value of a server setting that is not a secret.
	Value string `json:"value,omitempty"`
	// Secret settings report only IsSet.
	Secret bool  `json:"secret,omitempty"`
	IsSet  *bool `json:"is_set,omitempty"`
	// EnvVar is the environment variable behind a server setting, or the one
	// that bounds a console setting (Ceiling).
	EnvVar string `json:"env_var,omitempty"`
	// Ceiling: the environment value is an upper bound the console can only
	// tighten (a stolen console session cannot loosen it).
	Ceiling bool `json:"ceiling,omitempty"`
	// LockedBy names the environment variable that pins a console setting:
	// while it is set the console shows the value and cannot change it.
	LockedBy        string `json:"locked_by,omitempty"`
	RestartRequired bool   `json:"restart_required"`
	Page            string `json:"page,omitempty"`
	// Planned: a server setting scheduled to move into the console.
	Planned   bool       `json:"planned,omitempty"`
	ChangedAt *time.Time `json:"changed_at,omitempty"`
	ChangedBy string     `json:"changed_by,omitempty"`
}

// AdminDirectory resolves who last changed a console setting.
type AdminDirectory interface {
	GetByID(ctx context.Context, id shared.ID) (*admin.AdminUser, error)
}

// Builder builds the list. LookupEnv is os.LookupEnv in production.
type Builder struct {
	cfg       *config.Config
	settings  platformsetting.Repository
	admins    AdminDirectory
	lookupEnv func(string) (string, bool)
}

// NewBuilder creates a builder. settings and admins may be nil (then every
// console setting reports its default and no author).
func NewBuilder(cfg *config.Config, settings platformsetting.Repository, admins AdminDirectory, lookupEnv func(string) (string, bool)) *Builder {
	return &Builder{cfg: cfg, settings: settings, admins: admins, lookupEnv: lookupEnv}
}

// consoleSetting describes a setting stored in platform_settings.
type consoleSetting struct {
	key, group, page, ceilingEnv string
	// lockEnv: any of these variables, when set, pins the setting.
	lockEnv []string
	// defaultEnv: this variable is the default until the console stores a
	// value.
	defaultEnv string
}

// consoleSettings are the settings the console manages today.
var consoleSettings = []consoleSetting{
	{key: "signup_policy", group: GroupSignIn, page: "/system/sign-up", ceilingEnv: "SIGNUP_MODE"},
	{key: "self_service_default_limits", group: GroupSignIn, page: "/system/limits"},
	{key: "email.smtp", group: GroupEmail, page: "/system/email"},
	{key: "legal", group: GroupInstance, page: "/system/legal"},
	{key: "scan_approval_policy", group: GroupScanning, page: "/system/scan-approval"},
	{key: "platform_sensor_proof", group: GroupScanning, page: "/scanning/platform"},
	{key: "shared_sensors", group: GroupScanning, page: "/scanning/platform"},
	{key: "console_mfa_policy", group: GroupConsole, page: "/system/admin-sign-in"},
	{key: "version_check", group: GroupUpdates, page: "/system/software-updates", ceilingEnv: "VERSION_CHECK_ENABLED"},
	{key: "captcha.turnstile", group: GroupSignIn, page: "/system/captcha",
		lockEnv: []string{"CAPTCHA_TURNSTILE_SECRET", "CAPTCHA_TURNSTILE_SITE_KEY"}},
	{key: "deployment.region", group: GroupInstance, lockEnv: []string{"DEPLOYMENT_REGION"}}, // set on this page
	{key: "storage.tenant_quota_mb", group: GroupStorage, page: "/system/limits", defaultEnv: "STORAGE_TENANT_QUOTA_MB"},
	{key: "alerts.webhook", group: GroupAlerts, page: "/system/alerts"},
	{key: "ai.platform", group: GroupAI, page: "/system/ai-provider",
		lockEnv: []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"}},
}

// serverSetting describes a setting read from the environment at start.
type serverSetting struct {
	env, group string
	secret     bool
	planned    bool
	value      func(c *config.Config) string
	isSet      func(c *config.Config) bool
}

func boolText(b bool) string { return strconv.FormatBool(b) }

// serverSettings are the operator-facing server settings. Planned marks the
// ones the console is to take over (research note 177, configuration plan).
var serverSettings = []serverSetting{
	{env: "APP_URL", group: GroupInstance, value: func(c *config.Config) string { return c.App.URL }},
	{env: "ADMIN_PUBLIC_URL", group: GroupConsole, value: func(c *config.Config) string { return c.AdminPublicURL }},
	{env: "MANAGED_SERVICE", group: GroupInstance, value: func(c *config.Config) string { return boolText(c.App.ManagedService) }},
	{env: "SIGNUP_MODE", group: GroupSignIn, value: func(c *config.Config) string { return c.Auth.SignupMode }},
	{env: "SENSOR_PUBLIC_API_URL", group: GroupScanning, planned: true, value: func(c *config.Config) string { return c.SensorConfig.PublicAPIURL }},
	{env: "STORAGE_PROVIDER", group: GroupStorage, value: func(c *config.Config) string { return c.Storage.Provider }},
	{env: "ADMIN_ALLOWED_CIDRS", group: GroupConsole, value: func(c *config.Config) string { return strings.Join(c.AdminPlane.AllowedCIDRs, ", ") }},
	{env: "ADMIN_ELEVATION", group: GroupConsole, value: func(c *config.Config) string {
		if c.AdminElevationRequired {
			return "required"
		}
		return "off"
	}},
	{env: "OPENCTEM_PLANE", group: GroupConsole, value: func(c *config.Config) string { return c.AdminPlane.Plane }},
	{env: "ADMIN_AUDIT_SINK", group: GroupAudit, secret: true, isSet: func(c *config.Config) bool { return c.AdminAuditSink.URL != "" }},
	{env: "AUDIT_RETENTION_DAYS", group: GroupAudit, value: func(c *config.Config) string { return strconv.Itoa(c.AuditRetention.Days) }},
	{env: "AUDIT_RETENTION_ENABLED", group: GroupAudit, value: func(c *config.Config) string { return boolText(c.AuditRetention.Enabled) }},
	{env: "RATE_LIMIT_ENABLED", group: GroupInstance, value: func(c *config.Config) string { return boolText(c.RateLimit.Enabled) }},
	{env: "LOG_LEVEL", group: GroupInstance, planned: true, value: func(c *config.Config) string { return c.Log.Level }},
	{env: "VERSION_CHECK_ENABLED", group: GroupUpdates, value: func(c *config.Config) string { return boolText(c.Worker.VersionCheckEnabled) }},
}

// envAliases: rows that stand for several variables report environment when
// any of them is set.
var envAliases = map[string][]string{}

// Build returns every row: console settings first, then server settings.
func (b *Builder) Build(ctx context.Context) ([]Item, error) {
	items := make([]Item, 0, len(consoleSettings)+len(serverSettings))
	authors := map[string]string{}
	for _, cs := range consoleSettings {
		it := Item{Key: cs.key, Group: cs.group, Managed: ManagedConsole, Source: SourceDefault, Page: cs.page,
			EnvVar: cs.ceilingEnv, Ceiling: cs.ceilingEnv != ""}
		if cs.defaultEnv != "" {
			it.EnvVar = cs.defaultEnv
			if v, ok := b.lookupEnv(cs.defaultEnv); ok && strings.TrimSpace(v) != "" {
				it.Source = SourceEnvironment
			}
		}
		if b.settings != nil {
			st, err := b.settings.Get(ctx, cs.key)
			switch {
			case errors.Is(err, platformsetting.ErrNotFound):
			case err != nil:
				return nil, err
			default:
				it.Source = SourceConsole
				if st.Source == platformsetting.SourceEnvironment {
					it.Source = SourceEnvironment
				}
				if !st.UpdatedAt.IsZero() {
					at := st.UpdatedAt.UTC()
					it.ChangedAt = &at
				}
				if st.UpdatedBy != nil {
					it.ChangedBy = b.author(ctx, *st.UpdatedBy, authors)
				}
			}
		}
		for _, name := range cs.lockEnv {
			if v, ok := b.lookupEnv(name); ok && strings.TrimSpace(v) != "" {
				it.LockedBy, it.EnvVar, it.Source = name, name, SourceEnvironment
				it.ChangedAt, it.ChangedBy = nil, ""
				break
			}
		}
		items = append(items, it)
	}
	for _, ss := range serverSettings {
		it := Item{Key: ss.env, Group: ss.group, Managed: ManagedServer, Source: SourceDefault, EnvVar: ss.env,
			RestartRequired: true, Secret: ss.secret, Planned: ss.planned}
		for _, name := range aliasesOf(ss.env) {
			if _, ok := b.lookupEnv(name); ok {
				it.Source = SourceEnvironment
			}
		}
		if ss.secret {
			set := ss.isSet(b.cfg)
			it.IsSet = &set
		} else {
			it.Value = ss.value(b.cfg)
		}
		items = append(items, it)
	}
	return items, nil
}

func aliasesOf(env string) []string {
	if a, ok := envAliases[env]; ok {
		return a
	}
	return []string{env}
}

// author is the email of the administrator id, cached per build; "" when the
// administrator no longer exists.
func (b *Builder) author(ctx context.Context, id shared.ID, cache map[string]string) string {
	if v, ok := cache[id.String()]; ok {
		return v
	}
	email := ""
	if b.admins != nil {
		if a, err := b.admins.GetByID(ctx, id); err == nil {
			email = a.Email()
		}
	}
	cache[id.String()] = email
	return email
}
