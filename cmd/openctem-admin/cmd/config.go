package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Config types

type Config struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	CurrentContext string         `yaml:"current-context"`
	Contexts       []NamedContext `yaml:"contexts"`
}

type NamedContext struct {
	Name    string        `yaml:"name"`
	Context ContextDetail `yaml:"context"`
}

type ContextDetail struct {
	APIURL     string `yaml:"api-url"`
	APIKey     string `yaml:"api-key,omitempty"`
	APIKeyFile string `yaml:"api-key-file,omitempty"`
}

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openctem")
}

func configPath() string {
	return filepath.Join(configDir(), "config.yaml")
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	if cfg.APIVersion == "" {
		cfg.APIVersion = "admin.openctem.io/v1"
	}
	if cfg.Kind == "" {
		cfg.Kind = "Config"
	}

	if err := os.MkdirAll(configDir(), 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0600)
}

func (c *Config) GetContext(name string) *NamedContext {
	for i := range c.Contexts {
		if c.Contexts[i].Name == name {
			return &c.Contexts[i]
		}
	}
	return nil
}

func (c *Config) SetContext(name string, ctx ContextDetail) {
	for i := range c.Contexts {
		if c.Contexts[i].Name == name {
			c.Contexts[i].Context = ctx
			return
		}
	}
	c.Contexts = append(c.Contexts, NamedContext{Name: name, Context: ctx})
}

// Config subcommands

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
}

func init() {
	setCtxCmd := &cobra.Command{
		Use:   "set-context NAME",
		Short: "Create or update a context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			apiURL, _ := cmd.Flags().GetString("api-url")
			apiKey, _ := cmd.Flags().GetString("api-key")
			apiKeyFile, _ := cmd.Flags().GetString("api-key-file")

			if apiURL == "" {
				return fmt.Errorf("--api-url is required")
			}
			if apiKey == "" && apiKeyFile == "" {
				return fmt.Errorf("--api-key or --api-key-file is required")
			}

			cfg, err := loadConfig()
			if err != nil {
				cfg = &Config{}
			}

			cfg.SetContext(name, ContextDetail{
				APIURL:     apiURL,
				APIKey:     apiKey,
				APIKeyFile: apiKeyFile,
			})

			if cfg.CurrentContext == "" {
				cfg.CurrentContext = name
			}

			if err := saveConfig(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Printf("Context %q set.\n", name)
			if cfg.CurrentContext == name {
				fmt.Printf("Current context is %q.\n", name)
			}
			return nil
		},
	}
	setCtxCmd.Flags().String("api-url", "", "API URL")
	setCtxCmd.Flags().String("api-key", "", "API key")
	setCtxCmd.Flags().String("api-key-file", "", "Path to API key file")

	useCtxCmd := &cobra.Command{
		Use:   "use-context NAME",
		Short: "Switch to a different context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("no config found: %w", err)
			}

			if cfg.GetContext(name) == nil {
				return fmt.Errorf("context %q not found", name)
			}

			cfg.CurrentContext = name
			if err := saveConfig(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Printf("Switched to context %q.\n", name)
			return nil
		},
	}

	getCtxCmd := &cobra.Command{
		Use:   "get-contexts",
		Short: "List all configured contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("no config found: %w", err)
			}

			if flagOutput == outputJSON {
				printJSON(cfg.Contexts)
				return nil
			}
			if flagOutput == outputYAML {
				printYAML(cfg.Contexts)
				return nil
			}

			t := newTable("CURRENT", "NAME", "API-URL")
			for _, c := range cfg.Contexts {
				current := ""
				if c.Name == cfg.CurrentContext {
					current = "*"
				}
				t.AddRow(current, c.Name, c.Context.APIURL)
			}
			t.Flush()
			return nil
		},
	}

	curCtxCmd := &cobra.Command{
		Use:   "current-context",
		Short: "Show the current context",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("no config found: %w", err)
			}
			if cfg.CurrentContext == "" {
				fmt.Fprintln(os.Stderr, "No current context set.")
				return nil
			}
			fmt.Println(cfg.CurrentContext)
			return nil
		},
	}

	viewCmd := &cobra.Command{
		Use:   "view",
		Short: "Show the full configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("no config found: %w", err)
			}

			if flagOutput == outputJSON {
				printJSON(cfg)
				return nil
			}

			printYAML(cfg)
			return nil
		},
	}

	configCmd.AddCommand(setCtxCmd, useCtxCmd, getCtxCmd, curCtxCmd, viewCmd)
}
