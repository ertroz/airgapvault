package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/airgap/airgapvault/internal/crypto"
	"golang.org/x/term"
)

const (
	DefaultDirName  = ".airgapvault"
	DefaultFileName = "vault.agv"
	EnvVaultFile    = "AIRGAPVAULT_FILE"
)

var (
	ErrVaultExists   = errors.New("vault already exists")
	ErrVaultNotFound = errors.New("vault file not found")
	ErrNotFound      = errors.New("secret, environment, or project not found")
)

// VaultData represents the decrypted JSON structure of the vault.
type VaultData struct {
	Version  int                 `json:"version"`
	Projects map[string]*Project `json:"projects"`
}

// Project holds environments and their key-value secrets.
type Project struct {
	Environments map[string]map[string]string `json:"environments"`
}

// NewVaultData creates an initialized, empty VaultData.
func NewVaultData() *VaultData {
	return &VaultData{
		Version:  1,
		Projects: make(map[string]*Project),
	}
}

// ResolvePath determines the vault file path from flag, env var, or default.
func ResolvePath(flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	if envPath := os.Getenv(EnvVaultFile); envPath != "" {
		return envPath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, DefaultDirName, DefaultFileName), nil
}

// ParseTarget splits "<project>/<env>" into project and env names.
func ParseTarget(target string) (string, string, error) {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid target %q: expected <project>/<env>", target)
	}
	return parts[0], parts[1], nil
}

// Set adds or updates a secret under project/env.
func (v *VaultData) Set(project, env, key, value string) error {
	if project == "" || env == "" || key == "" {
		return errors.New("project, env, and key must not be empty")
	}
	if strings.Contains(project, "/") || strings.Contains(env, "/") {
		return errors.New("project and env names must not contain '/'")
	}
	if v.Projects == nil {
		v.Projects = make(map[string]*Project)
	}
	p, ok := v.Projects[project]
	if !ok || p == nil {
		p = &Project{Environments: make(map[string]map[string]string)}
		v.Projects[project] = p
	}
	if p.Environments == nil {
		p.Environments = make(map[string]map[string]string)
	}
	e, ok := p.Environments[env]
	if !ok || e == nil {
		e = make(map[string]string)
		p.Environments[env] = e
	}
	e[key] = value
	return nil
}

// Get retrieves a single secret value.
func (v *VaultData) Get(project, env, key string) (string, bool) {
	p, ok := v.Projects[project]
	if !ok || p == nil {
		return "", false
	}
	e, ok := p.Environments[env]
	if !ok || e == nil {
		return "", false
	}
	val, ok := e[key]
	return val, ok
}

// GetEnv retrieves all secrets for a project/env.
func (v *VaultData) GetEnv(project, env string) (map[string]string, bool) {
	p, ok := v.Projects[project]
	if !ok || p == nil {
		return nil, false
	}
	e, ok := p.Environments[env]
	if !ok || e == nil {
		return nil, false
	}
	return e, true
}

// DeleteKey removes a single key from project/env.
func (v *VaultData) DeleteKey(project, env, key string) bool {
	e, ok := v.GetEnv(project, env)
	if !ok {
		return false
	}
	if _, exists := e[key]; !exists {
		return false
	}
	delete(e, key)
	return true
}

// DeleteEnv removes an entire environment from a project.
func (v *VaultData) DeleteEnv(project, env string) bool {
	p, ok := v.Projects[project]
	if !ok || p == nil {
		return false
	}
	if _, exists := p.Environments[env]; !exists {
		return false
	}
	delete(p.Environments, env)
	return true
}

// DeleteProject removes an entire project from the vault.
func (v *VaultData) DeleteProject(project string) bool {
	if _, exists := v.Projects[project]; !exists {
		return false
	}
	delete(v.Projects, project)
	return true
}

// SortedKeys returns sorted keys from a string map.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Load reads and decrypts a vault file into memory.
func Load(path string, secret []byte) (*VaultData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrVaultNotFound, path)
		}
		return nil, fmt.Errorf("failed to read vault: %w", err)
	}

	plaintext, err := crypto.Decrypt(raw, secret)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("failed to parse vault JSON: %w", err)
	}
	if data.Projects == nil {
		data.Projects = make(map[string]*Project)
	}
	return &data, nil
}

// Save encrypts and atomically writes the vault to disk using a temp file + rename.
func Save(path string, data *VaultData, secret []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal vault: %w", err)
	}
	defer clear(plaintext)

	encrypted, err := crypto.Encrypt(plaintext, secret)
	if err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp vault file: %w", err)
	}
	tmpPath := tmpFile.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to set temp file permissions: %w", err)
	}

	if _, err := tmpFile.Write(encrypted); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write temp vault file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync temp vault file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp vault file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to atomically replace vault file: %w", err)
	}
	cleanup = false
	return nil
}

// ReadKeyfile reads a keyfile from disk and strips trailing CR/LF.
func ReadKeyfile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile %q: %w", path, err)
	}
	trimmed := bytes.TrimRight(data, "\r\n")
	if len(trimmed) == 0 {
		clear(data)
		return nil, errors.New("keyfile is empty")
	}
	return trimmed, nil
}

// ResolveAuth returns the master secret from keyfile (if provided) or masked terminal prompt.
func ResolveAuth(keyfile string, prompt string) ([]byte, error) {
	if keyfile != "" {
		return ReadKeyfile(keyfile)
	}
	return PromptPassphrase(prompt)
}

// PromptPassphrase reads a passphrase without echoing to the terminal.
func PromptPassphrase(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	var tty *os.File
	if !term.IsTerminal(fd) {
		var err error
		tty, err = os.Open("/dev/tty")
		if err != nil {
			return nil, errors.New("cannot prompt for passphrase: no interactive terminal (use --keyfile)")
		}
		defer tty.Close()
		fd = int(tty.Fd())
	}

	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	if len(pw) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}
	return pw, nil
}

// PromptNewPassphrase prompts twice for a new passphrase and ensures both match.
func PromptNewPassphrase(prompt, confirmPrompt string) ([]byte, error) {
	pw1, err := PromptPassphrase(prompt)
	if err != nil {
		return nil, err
	}
	pw2, err := PromptPassphrase(confirmPrompt)
	if err != nil {
		clear(pw1)
		return nil, err
	}
	defer clear(pw2)

	if !bytes.Equal(pw1, pw2) {
		clear(pw1)
		return nil, errors.New("passphrases do not match")
	}
	return pw1, nil
}
