package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
)

// malformedConfig has a mis-indented `preference` key under the first RTR
// cache — the shape of typo an operator actually makes.
const malformedConfig = `bmp:
  listen: ":11019"
rtr:
  caches:
    - address: "127.0.0.1:3323"
       preference: 1
      transport: tcp
`

const validConfig = `bmp:
  listen: ":11019"
rtr:
  caches:
    - address: "127.0.0.1:3323"
      preference: 1
      transport: tcp
`

// loadConfigFile points the CLI at a config file holding body and runs the
// same initialization cobra runs, returning nothing: the outcome is in
// configReadErr. The previous cfgFile is restored when the test ends so the
// rest of the package is unaffected.
func loadConfigFile(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raven.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prev := cfgFile
	t.Cleanup(func() {
		cfgFile = prev
		configReadErr = nil
	})
	cfgFile = path
	initConfig()
}

// ─── TestConfigParseErrorIsFatal ───

// A raven.yaml that exists but does not parse must stop RAVEN rather than
// silently fall back to defaults. Falling back started a daemon with
// rtr_caches:0, no BMP peers and no event rules, exiting 0 — a typo that
// looked healthy from the outside.
func TestConfigParseErrorIsFatal(t *testing.T) {
	loadConfigFile(t, malformedConfig)

	if configReadErr == nil {
		t.Fatal("configReadErr = nil after a malformed config, want the parse error recorded")
	}
	if !strings.Contains(configReadErr.Error(), "did not find expected key") {
		t.Errorf("configReadErr = %q, want it to carry the YAML parse failure", configReadErr)
	}
	if !strings.Contains(configReadErr.Error(), "raven.yaml") {
		t.Errorf("configReadErr = %q, want it to name the offending file", configReadErr)
	}

	// Every command must refuse to run, serve above all: PersistentPreRunE is
	// what cobra consults before RunE, so a non-nil return here is exactly
	// what keeps the daemon from starting and makes main exit 1.
	for _, cmd := range []*cobra.Command{serveCmd, versionCmd, statusCmd, checkCmd} {
		err := rootCmd.PersistentPreRunE(cmd, nil)
		if err == nil {
			t.Errorf("%s: PersistentPreRunE = nil, want the config parse error", cmd.Name())
			continue
		}
		if !strings.Contains(err.Error(), "did not find expected key") {
			t.Errorf("%s: error = %q, want it to carry the YAML parse failure", cmd.Name(), err)
		}
	}
}

// Execute must surface the parse error to main, which is what turns it into a
// non-zero exit. This drives the real command path rather than calling
// PersistentPreRunE directly, and uses `version` — a command that needs no
// daemon and no network, and that previously exited 0 with a broken config on
// disk.
func TestExecuteFailsOnMalformedConfig(t *testing.T) {
	loadConfigFile(t, malformedConfig)

	prevArgs := rootCmd.Flags().Args()
	t.Cleanup(func() { rootCmd.SetArgs(prevArgs) })
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("Execute() = nil for a malformed config, want an error — main exits 1 only on a non-nil error")
	}
}

// The complement: a config that parses must not be rejected, and neither must
// an absent one. RAVEN has always run on defaults when no raven.yaml exists
// and that stays true — only a file that is present and broken is fatal.
func TestConfigReadErrorOnlyForMalformedFiles(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		loadConfigFile(t, validConfig)
		if configReadErr != nil {
			t.Errorf("configReadErr = %v, want nil for a config that parses", configReadErr)
		}
	})

	t.Run("missing config file", func(t *testing.T) {
		prev := cfgFile
		t.Cleanup(func() {
			cfgFile = prev
			configReadErr = nil
		})
		// No --config and no raven.yaml in the package directory, so the
		// search finds nothing.
		cfgFile = ""
		initConfig()

		if configReadErr != nil {
			t.Errorf("configReadErr = %v, want nil when no config file exists", configReadErr)
		}
	})
}

// ─── TestInitConfigAppliesEnvOverrides ───

// The reported bug, end to end through initConfig: bmp.listen in the file
// and RAVEN_BMP_LISTEN in the environment, and serve logged the file value.
func TestInitConfigAppliesEnvOverrides(t *testing.T) {
	t.Setenv("RAVEN_BMP_LISTEN", "127.0.0.1:21119")
	loadConfigFile(t, "bmp:\n  listen: 127.0.0.1:21019\n")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.BMP.Listen != "127.0.0.1:21119" {
		t.Errorf("BMP.Listen = %q, want the RAVEN_BMP_LISTEN value 127.0.0.1:21119", cfg.BMP.Listen)
	}
}
