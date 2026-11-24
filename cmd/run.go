package cmd

import (
	"fmt"
	"os"

	"github.com/airgap/airgapvault/internal/runner"
	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var (
	runProject string
	runEnv     string
)

var runCmd = &cobra.Command{
	Use:   "run -p <project> -e <env> -- <command...>",
	Short: "Decrypt secrets in memory and run a command with them injected",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if runProject == "" || runEnv == "" {
			return fmt.Errorf("both --project (-p) and --env (-e) are required")
		}

		path, err := resolveVaultPath()
		if err != nil {
			return err
		}

		secret, err := resolveAuth("Enter master passphrase: ")
		if err != nil {
			return err
		}
		defer clear(secret)

		v, err := vault.Load(path, secret)
		if err != nil {
			return err
		}

		secrets, ok := v.GetEnv(runProject, runEnv)
		if !ok {
			return fmt.Errorf("%w: %s/%s", vault.ErrNotFound, runProject, runEnv)
		}

		code := runner.Run(args, secrets, os.Stdin, os.Stdout, os.Stderr)
		if code != 0 {
			return exitError{code: code}
		}
		return nil
	},
}

func init() {
	runCmd.Flags().StringVarP(&runProject, "project", "p", "", "project name (required)")
	runCmd.Flags().StringVarP(&runEnv, "env", "e", "", "environment name (required)")
	rootCmd.AddCommand(runCmd)
}
