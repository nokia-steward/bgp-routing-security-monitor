package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
)

var cfgFile string
var addr string

// configReadErr records a config file that exists but could not be read or
// parsed. initConfig runs from cobra.OnInitialize, which cannot return an
// error, so the failure is stashed here and rootCmd's PersistentPreRunE turns
// it into a fatal one.
//
// A malformed config must never be defaulted away: silently falling back
// would start a daemon with no RTR caches, no BMP peers and no event rules
// from a single typo, which looks healthy from the outside. This matches how
// semantic config errors already behave — config.Load returns them and serve
// aborts.
var configReadErr error

var rootCmd = &cobra.Command{
	Use:   "raven",
	Short: "RAVEN — Routing Analysis, Validation, and Event Network",
	Long: `RAVEN correlates live BMP feeds, RPKI ROV, and ASPA path validation
into a unified, operator-facing workflow.

Ravens see what you can't.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	// Refuse to run any subcommand on a config we could not parse. Returning
	// the error here means main prints it to stderr and exits 1, and RunE —
	// including serve's — is never reached.
	PersistentPreRunE: func(*cobra.Command, []string) error { return configReadErr },
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./raven.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level: debug, info, warn, error")
	rootCmd.PersistentFlags().String("log-format", "json", "log format: json, text")
	rootCmd.PersistentFlags().StringVar(&addr, "address", "localhost:11020", "RAVEN daemon address for CLI queries")

	// Bind flags to viper
	viper.BindPFlag("logging.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("logging.format", rootCmd.PersistentFlags().Lookup("log-format"))

	// Register subcommands
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(peersCmd)
	rootCmd.AddCommand(routesCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(newWatchCmd(&addr))
	rootCmd.AddCommand(newWhatIfCmd(&addr))
	rootCmd.AddCommand(newASPACmd(&addr))
	rootCmd.AddCommand(newAuditCmd(&addr))
	rootCmd.AddCommand(newFlowspecCmd(&addr))
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(newRTRCmd())
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("raven")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/raven")
	}

	config.ConfigureEnv()

	configReadErr = nil
	if err := viper.ReadInConfig(); err != nil {
		// No config file at all is fine: RAVEN runs on defaults. A file that
		// is present but unparseable is fatal — see configReadErr.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			path := viper.ConfigFileUsed()
			if path == "" {
				path = "config"
			}
			configReadErr = fmt.Errorf("reading %s: %w", path, err)
		}
	}
}

// initLogger creates a structured logger based on config.
func initLogger() *slog.Logger {
	level := slog.LevelInfo
	switch viper.GetString("logging.level") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if viper.GetString("logging.format") == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}
