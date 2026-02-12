package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	version string

	// Global flags
	flagAPIURL  string
	flagAPIKey  string
	flagContext string
	flagOutput  string
	flagVerbose bool
)

var rootCmd = &cobra.Command{
	Use:   "openctem-admin",
	Short: "OpenCTEM platform administration CLI",
	Long: `openctem-admin is a kubectl-style CLI for managing the OpenCTEM platform.

It provides commands to manage admin users, view audit logs,
configure target mappings, and monitor platform health.

Use "openctem-admin config set-context" to configure your connection.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

// SetVersion sets the CLI version from build flags.
func SetVersion(v string) {
	version = v
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&flagAPIURL, "api-url", "", "Override API URL (env: OPENCTEM_API_URL)")
	rootCmd.PersistentFlags().StringVar(&flagAPIKey, "api-key", "", "Override API key (env: OPENCTEM_API_KEY)")
	rootCmd.PersistentFlags().StringVarP(&flagContext, "context", "c", "", "Use specific context (env: OPENCTEM_CONTEXT)")
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "table", "Output format: table, wide, json, yaml")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose output")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(clusterInfoCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(describeCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(rotateKeyCmd)
	rootCmd.AddCommand(auditStatsCmd)
}

func initConfig() {
	if flagAPIURL == "" {
		flagAPIURL = os.Getenv("OPENCTEM_API_URL")
	}
	if flagAPIKey == "" {
		flagAPIKey = os.Getenv("OPENCTEM_API_KEY")
	}

	if flagAPIURL == "" || flagAPIKey == "" {
		u, k := resolveFromConfigFile()
		if flagAPIURL == "" {
			flagAPIURL = u
		}
		if flagAPIKey == "" {
			flagAPIKey = k
		}
	}
}

func resolveFromConfigFile() (string, string) {
	ctxName := flagContext
	if ctxName == "" {
		ctxName = os.Getenv("OPENCTEM_CONTEXT")
	}

	cfg, err := loadConfig()
	if err != nil {
		return "", ""
	}

	if ctxName == "" {
		ctxName = cfg.CurrentContext
	}

	ctx := cfg.GetContext(ctxName)
	if ctx == nil {
		return "", ""
	}

	apiKey := ctx.Context.APIKey
	if apiKey == "" && ctx.Context.APIKeyFile != "" {
		data, err := os.ReadFile(expandPath(ctx.Context.APIKeyFile))
		if err == nil {
			apiKey = string(data)
		}
	}

	return ctx.Context.APIURL, apiKey
}

func mustClient() *Client {
	if flagAPIURL == "" {
		fmt.Fprintln(os.Stderr, "Error: API URL not configured. Use --api-url, OPENCTEM_API_URL, or 'openctem-admin config set-context'")
		os.Exit(1)
	}
	if flagAPIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key not configured. Use --api-key, OPENCTEM_API_KEY, or 'openctem-admin config set-context'")
		os.Exit(1)
	}
	return NewClient(flagAPIURL, flagAPIKey, flagVerbose)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show CLI version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("openctem-admin version %s\n", version)
		fmt.Printf("  Go:       %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

var clusterInfoCmd = &cobra.Command{
	Use:   "cluster-info",
	Short: "Display platform connection status",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := mustClient()
		data, err := client.Get("/api/v1/admin/auth/validate")
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}

		var resp ValidateResponse
		if err := unmarshal(data, &resp); err != nil {
			return err
		}

		if flagOutput == outputJSON {
			printJSON(resp)
			return nil
		}
		if flagOutput == outputYAML {
			printYAML(resp)
			return nil
		}

		fmt.Fprintf(os.Stdout, "OpenCTEM Platform\n")
		fmt.Fprintf(os.Stdout, "  API URL:  %s\n", flagAPIURL)
		fmt.Fprintf(os.Stdout, "  Status:   connected\n")
		fmt.Fprintf(os.Stdout, "\nAuthenticated as:\n")
		fmt.Fprintf(os.Stdout, "  ID:    %s\n", resp.ID)
		fmt.Fprintf(os.Stdout, "  Email: %s\n", resp.Email)
		fmt.Fprintf(os.Stdout, "  Name:  %s\n", resp.Name)
		fmt.Fprintf(os.Stdout, "  Role:  %s\n", resp.Role)
		return nil
	},
}
