package cli

import "github.com/spf13/cobra"

// newRTRCmd builds the parent "rtr" command group. It has no RunE of its own;
// invoking it bare prints help listing the subcommands.
func newRTRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rtr",
		Short: "RTR cache session tools",
		Long:  "Tools for observing and interacting with RPKI-to-Router (RTR) cache sessions.",
	}

	cmd.AddCommand(newRTRMonitorCmd())
	cmd.AddCommand(newRTRSeedBaselineCmd())
	cmd.AddCommand(newRTRDumpCmd())

	return cmd
}
