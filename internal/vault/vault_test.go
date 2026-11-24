package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultSaveLoadAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "sub", "vault.agv")
	pass := []byte("test-passphrase")

	v := NewVaultData()
	if err := v.Set("myapp", "prod", "DB_PASS", "s3cr3t"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if err := v.Set("myapp", "dev", "DEBUG", "true"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if err := Save(vaultPath, v, pass); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", perm)
	}

	// Verify no leftover .tmp files
	entries, err := os.ReadDir(filepath.Dir(vaultPath))
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("found leftover temp file: %s", e.Name())
		}
	}

	loaded, err := Load(vaultPath, pass)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	val, ok := loaded.Get("myapp", "prod", "DB_PASS")
	if !ok || val != "s3cr3t" {
		t.Fatalf("got (%q, %v), want (%q, true)", val, ok, "s3cr3t")
	}
}

func TestParseDotenv(t *testing.T) {
	input := `
# Full line comment
   # Indented comment

PLAIN=hello_world
export EXPORTED_VAR=exported_value
WITH_INLINE=value123 # inline comment
SINGLE_QUOTED='hello # not a comment'
DOUBLE_QUOTED="line1\nline2\t\"quoted\"\\slash" # trailing comment
EMPTY_VAL=
QUOTED_EMPTY=""
URL=https://example.com?a=1&b=2
`
	got, err := ParseDotenv(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseDotenv failed: %v", err)
	}

	expected := map[string]string{
		"PLAIN":         "hello_world",
		"EXPORTED_VAR":  "exported_value",
		"WITH_INLINE":   "value123",
		"SINGLE_QUOTED": "hello # not a comment",
		"DOUBLE_QUOTED": "line1\nline2\t\"quoted\"\\slash",
		"EMPTY_VAL":     "",
		"QUOTED_EMPTY":  "",
		"URL":           "https://example.com?a=1&b=2",
	}

	if len(got) != len(expected) {
		t.Fatalf("expected %d keys, got %d: %#v", len(expected), len(got), got)
	}
	for k, want := range expected {
		if got[k] != want {
			t.Errorf("key %q: got %q, want %q", k, got[k], want)
		}
	}
}

func TestFormatDotenvRoundTrip(t *testing.T) {
	orig := map[string]string{
		"SIMPLE":    "abc",
		"SPACES":    "hello world",
		"MULTILINE": "a\nb",
		"HASH":      "val#1",
		"EMPTY":     "",
	}

	formatted := FormatDotenv(orig)
	parsed, err := ParseDotenv(strings.NewReader(formatted))
	if err != nil {
		t.Fatalf("ParseDotenv(FormatDotenv) failed: %v", err)
	}
	for k, want := range orig {
		if parsed[k] != want {
			t.Errorf("round-trip mismatch for %q: got %q, want %q", k, parsed[k], want)
		}
	}
}
