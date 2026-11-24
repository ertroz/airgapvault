package runner

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunInjectsEnvAndOverridesExisting(t *testing.T) {
	t.Setenv("AIRGAP_OVERRIDE_TEST", "old_value")

	secrets := map[string]string{
		"AIRGAP_INJECTED_SECRET": "super_secret_42",
		"AIRGAP_OVERRIDE_TEST":   "new_value",
	}

	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"sh", "-c", `printf "%s|%s" "$AIRGAP_INJECTED_SECRET" "$AIRGAP_OVERRIDE_TEST"`},
		secrets,
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if got, want := stdout.String(), "super_secret_42|new_value"; got != want {
		t.Fatalf("got stdout %q, want %q", got, want)
	}
}

func TestRunPropagatesExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"sh", "-c", "exit 42"},
		map[string]string{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 42 {
		t.Fatalf("expected exit code 42, got %d", code)
	}
}

func TestMergeEnvDoesNotMutateParentEnv(t *testing.T) {
	const key = "AIRGAP_PARENT_CHECK"
	os.Unsetenv(key)

	merged := MergeEnv(os.Environ(), map[string]string{key: "child_only"})
	found := false
	for _, e := range merged {
		if e == key+"=child_only" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected merged env to contain injected key")
	}
	if _, exists := os.LookupEnv(key); exists {
		t.Fatal("parent process environment was unexpectedly mutated")
	}
}
