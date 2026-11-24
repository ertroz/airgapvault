package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// MergeEnv merges secrets into base environment variables (KEY=VALUE slices).
// Secrets override any pre-existing keys in base.
func MergeEnv(base []string, secrets map[string]string) []string {
	merged := make([]string, 0, len(base)+len(secrets))
	seen := make(map[string]bool, len(secrets))

	for _, entry := range base {
		k, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if val, override := secrets[k]; override {
			if !seen[k] {
				merged = append(merged, k+"="+val)
				seen[k] = true
			}
			continue
		}
		merged = append(merged, entry)
	}

	for k, val := range secrets {
		if !seen[k] {
			merged = append(merged, k+"="+val)
		}
	}

	return merged
}

// Run executes args[0] with args[1:] in a child process, injecting secrets into
// its environment, forwarding stdin/stdout/stderr and SIGINT/SIGTERM, and returning
// the child's exit code.
func Run(args []string, secrets map[string]string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: no command specified")
		return 1
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = MergeEnv(os.Environ(), secrets)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "error starting %q: %v\n", args[0], err)
		return 1
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	doneCh := make(chan struct{})

	go func() {
		for {
			select {
			case sig := <-sigCh:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-doneCh:
				return
			}
		}
	}()

	err := cmd.Wait()
	signal.Stop(sigCh)
	close(doneCh)

	if err == nil {
		return 0
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}

	fmt.Fprintf(stderr, "error waiting for %q: %v\n", args[0], err)
	return 1
}
