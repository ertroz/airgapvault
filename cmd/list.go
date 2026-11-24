package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var listReveal bool

var listCmd = &cobra.Command{
	Use:   "list [<project>[/<env>]]",
	Short: "List projects, environments, or secret keys",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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

		// No args: list projects
		if len(args) == 0 {
			projects := vault.SortedKeys(v.Projects)
			if len(projects) == 0 {
				fmt.Fprintln(os.Stdout, "(vault is empty)")
				return nil
			}
			for _, p := range projects {
				fmt.Fprintln(os.Stdout, p)
			}
			return nil
		}

		target := args[0]
		if !strings.Contains(target, "/") {
			// Project specified: list environments
			p, ok := v.Projects[target]
			if !ok || p == nil {
				return fmt.Errorf("%w: project %q", vault.ErrNotFound, target)
			}
			envs := vault.SortedKeys(p.Environments)
			if len(envs) == 0 {
				fmt.Fprintf(os.Stdout, "(no environments in %s)\n", target)
				return nil
			}
			for _, e := range envs {
				fmt.Fprintf(os.Stdout, "%s (%d keys)\n", e, len(p.Environments[e]))
			}
			return nil
		}

		// <project>/<env> specified: list keys (and values if --reveal)
		project, env, err := vault.ParseTarget(target)
		if err != nil {
			return err
		}
		secrets, ok := v.GetEnv(project, env)
		if !ok {
			return fmt.Errorf("%w: %s/%s", vault.ErrNotFound, project, env)
		}
		keys := vault.SortedKeys(secrets)
		if len(keys) == 0 {
			fmt.Fprintf(os.Stdout, "(no secrets in %s/%s)\n", project, env)
			return nil
		}
		for _, k := range keys {
			if listReveal {
				fmt.Fprintf(os.Stdout, "%s=%s\n", k, secrets[k])
			} else {
				fmt.Fprintln(os.Stdout, k)
			}
		}
		return nil
	},
}

func init() {
	listCmd.Flags().BoolVar(&listReveal, "reveal", false, "reveal secret values when listing a project/env")
	rootCmd.AddCommand(listCmd)
}
