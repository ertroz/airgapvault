package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set <project>/<env> <KEY>[=<VALUE>]",
	Short: "Add or update a secret in the vault",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		project, env, err := vault.ParseTarget(args[0])
		if err != nil {
			return err
		}

		var key, value string
		if k, v, hasEq := strings.Cut(args[1], "="); hasEq {
			key = strings.TrimSpace(k)
			value = v
			if key == "" {
				return fmt.Errorf("key must not be empty")
			}
		} else {
			key = strings.TrimSpace(args[1])
			if key == "" {
				return fmt.Errorf("key must not be empty")
			}
			valBytes, err := vault.PromptPassphrase(fmt.Sprintf("Enter value for %s: ", key))
			if err != nil {
				return err
			}
			value = string(valBytes)
			clear(valBytes)
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

		if err := v.Set(project, env, key, value); err != nil {
			return err
		}

		if err := vault.Save(path, v, secret); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Saved %s in %s/%s\n", key, project, env)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
}
