package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/airgap/airgapvault/internal/vault"
	"github.com/spf13/cobra"
)

var (
	flagVault   string
	flagKeyfile string
	exitCode    int
)

// exitError allows commands like `run` to propagate a specific child exit code.
type exitError struct {
	code int
}

func (e exitError) Error() string {
	return fmt.Sprintf("exit status %d", e.code)
}

var rootCmd = &cobra.Command{
	Use:           "airgapvault",
	Short:         "Offline-first encrypted secret & environment variable manager",
	Long:          "airgapvault eliminates plaintext .env files on disk by storing secrets in an Argon2id + AES-256-GCM encrypted vault and injecting them directly into child process memory.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagVault, "vault", "", "path to vault file (overrides AIRGAPVAULT_FILE and ~/.airgapvault/vault.agv)")
	rootCmd.PersistentFlags().StringVar(&flagKeyfile, "keyfile", "", "path to keyfile for non-interactive unlock")
}

// Execute runs the root command and returns the process exit code.
func Execute() int {
	exitCode = 0
	if err := rootCmd.Execute(); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			return ee.code
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return exitCode
}

func resolveVaultPath() (string, error) {
	return vault.ResolvePath(flagVault)
}

func resolveAuth(prompt string) ([]byte, error) {
	return vault.ResolveAuth(flagKeyfile, prompt)
}
