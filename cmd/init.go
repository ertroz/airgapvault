package cmd

import (
	"fmt"
	"os"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var initForce bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new encrypted vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveVaultPath()
		if err != nil {
			return err
		}

		if !initForce {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%w at %s (use --force to overwrite)", vault.ErrVaultExists, path)
			}
		}

		var secret []byte
		if flagKeyfile != "" {
			secret, err = vault.ReadKeyfile(flagKeyfile)
		} else {
			secret, err = vault.PromptNewPassphrase("Enter new master passphrase: ", "Confirm master passphrase: ")
		}
		if err != nil {
			return err
		}
		defer clear(secret)

		v := vault.NewVaultData()
		if err := vault.Save(path, v, secret); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Initialized empty vault at %s\n", path)
		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "overwrite existing vault if present")
	rootCmd.AddCommand(initCmd)
}
