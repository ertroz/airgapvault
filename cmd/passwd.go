package cmd

import (
	"fmt"
	"os"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var newKeyfile string

var passwdCmd = &cobra.Command{
	Use:   "passwd",
	Short: "Change the master passphrase or keyfile and re-encrypt the vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveVaultPath()
		if err != nil {
			return err
		}

		oldSecret, err := resolveAuth("Enter current master passphrase: ")
		if err != nil {
			return err
		}
		defer clear(oldSecret)

		v, err := vault.Load(path, oldSecret)
		if err != nil {
			return err
		}

		var newSecret []byte
		if newKeyfile != "" {
			newSecret, err = vault.ReadKeyfile(newKeyfile)
		} else {
			newSecret, err = vault.PromptNewPassphrase("Enter new master passphrase: ", "Confirm new master passphrase: ")
		}
		if err != nil {
			return err
		}
		defer clear(newSecret)

		if err := vault.Save(path, v, newSecret); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Vault re-encrypted successfully at %s\n", path)
		return nil
	},
}

func init() {
	passwdCmd.Flags().StringVar(&newKeyfile, "new-keyfile", "", "path to new keyfile for re-encryption")
	rootCmd.AddCommand(passwdCmd)
}
