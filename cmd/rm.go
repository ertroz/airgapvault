package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var rmYes bool

var rmCmd = &cobra.Command{
	Use:   "rm <project>[/<env> [<KEY>]]",
	Short: "Remove a secret key, environment, or project",
	Args:  cobra.RangeArgs(1, 2),
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

		target := args[0]

		if len(args) == 2 {
			// Remove a single key
			project, env, err := vault.ParseTarget(target)
			if err != nil {
				return err
			}
			key := args[1]
			if !v.DeleteKey(project, env, key) {
				return fmt.Errorf("%w: %s/%s %s", vault.ErrNotFound, project, env, key)
			}
			if err := vault.Save(path, v, secret); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Removed %s from %s/%s\n", key, project, env)
			return nil
		}

		// Removing an entire env or project requires confirmation unless --yes
		if strings.Contains(target, "/") {
			project, env, err := vault.ParseTarget(target)
			if err != nil {
				return err
			}
			if _, ok := v.GetEnv(project, env); !ok {
				return fmt.Errorf("%w: %s/%s", vault.ErrNotFound, project, env)
			}
			if !rmYes && !confirmPrompt(fmt.Sprintf("Delete entire environment %s/%s? [y/N]: ", project, env)) {
				fmt.Fprintln(os.Stdout, "Aborted.")
				return nil
			}
			v.DeleteEnv(project, env)
			if err := vault.Save(path, v, secret); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Removed environment %s/%s\n", project, env)
			return nil
		}

		project := target
		if _, ok := v.Projects[project]; !ok {
			return fmt.Errorf("%w: project %q", vault.ErrNotFound, project)
		}
		if !rmYes && !confirmPrompt(fmt.Sprintf("Delete entire project %q and all its environments? [y/N]: ", project)) {
			fmt.Fprintln(os.Stdout, "Aborted.")
			return nil
		}
		v.DeleteProject(project)
		if err := vault.Save(path, v, secret); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Removed project %q\n", project)
		return nil
	},
}

func confirmPrompt(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

func init() {
	rmCmd.Flags().BoolVarP(&rmYes, "yes", "y", false, "skip confirmation prompt when deleting an environment or project")
	rootCmd.AddCommand(rmCmd)
}
