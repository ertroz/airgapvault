package cmd

import (
	"fmt"
	"os"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var importDeleteSource bool

var importCmd = &cobra.Command{
	Use:   "import <project>/<env> <path-to-.env>",
	Short: "Import secrets from an existing .env file into the vault",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		project, env, err := vault.ParseTarget(args[0])
		if err != nil {
			return err
		}
		dotenvPath := args[1]

		f, err := os.Open(dotenvPath)
		if err != nil {
			return fmt.Errorf("failed to open %q: %w", dotenvPath, err)
		}
		parsed, parseErr := vault.ParseDotenv(f)
		_ = f.Close()
		if parseErr != nil {
			return fmt.Errorf("failed to parse %q: %w", dotenvPath, parseErr)
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

		for k, val := range parsed {
			if err := v.Set(project, env, k, val); err != nil {
				return err
			}
		}

		if err := vault.Save(path, v, secret); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Imported %d secrets into %s/%s\n", len(parsed), project, env)

		if importDeleteSource {
			if err := os.Remove(dotenvPath); err != nil {
				return fmt.Errorf("imported successfully, but failed to delete source %q: %w", dotenvPath, err)
			}
			fmt.Fprintf(os.Stdout, "Deleted source file %s\n", dotenvPath)
		}
		return nil
	},
}

func init() {
	importCmd.Flags().BoolVar(&importDeleteSource, "delete-source", false, "delete the source .env file after successful import")
	rootCmd.AddCommand(importCmd)
}
