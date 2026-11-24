package cmd

import (
	"fmt"
	"os"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var exportFormat string

var exportCmd = &cobra.Command{
	Use:   "export <project>/<env>",
	Short: "Export secrets to stdout (fallback for manual .env generation)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if exportFormat != "dotenv" {
			return fmt.Errorf("unsupported format %q (supported: dotenv)", exportFormat)
		}

		project, env, err := vault.ParseTarget(args[0])
		if err != nil {
			return err
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

		secrets, ok := v.GetEnv(project, env)
		if !ok {
			return fmt.Errorf("%w: %s/%s", vault.ErrNotFound, project, env)
		}

		fmt.Fprint(os.Stdout, vault.FormatDotenv(secrets))
		return nil
	},
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "dotenv", "output format (dotenv)")
	rootCmd.AddCommand(exportCmd)
}
