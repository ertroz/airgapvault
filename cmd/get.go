package cmd

import (
	"fmt"
	"os"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var getCmd = &cobra.Command{
	Use:   "get <project>/<env> <KEY>",
	Short: "Retrieve a single secret value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		project, env, err := vault.ParseTarget(args[0])
		if err != nil {
			return err
		}
		key := args[1]

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

		val, ok := v.Get(project, env, key)
		if !ok {
			return fmt.Errorf("%w: %s/%s %s", vault.ErrNotFound, project, env, key)
		}

		if term.IsTerminal(int(os.Stdout.Fd())) {
			fmt.Fprintln(os.Stdout, val)
		} else {
			fmt.Fprint(os.Stdout, val)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
