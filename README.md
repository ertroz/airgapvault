# airgapvault

`airgapvault` is an offline-first, single-binary secret and environment variable manager written in Go. It eliminates the need to store plaintext `.env` files in project directories by keeping secrets in an encrypted vault and injecting them directly into child process memory at runtime.

## Core Principles

- **Zero plaintext `.env` on disk**: Secrets are decrypted only in memory and injected directly into the child process environment via `airgapvault run`.
- **100% Offline & Portable**: No cloud services, daemons, or network access required. Just one static binary and one encrypted `.agv` file.
- **Authenticated Encryption**: Uses **Argon2id** (`time=3`, `memory=64 MiB`, `threads=4`) for key derivation and **AES-256-GCM** with authenticated header metadata (AAD). Every write generates a fresh random salt & nonce and performs an atomic write (`temp file + fsync + rename`).

## Build (Static Binary)

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o airgapvault .
```

To cross-compile for another airgapped Linux/macOS host:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o airgapvault .
```

## Quick Start

### 1. Initialize a vault
By default, the vault is stored at `~/.airgapvault/vault.agv` (override with `--vault <path>` or `AIRGAPVAULT_FILE`).

```bash
# Interactive masked passphrase (prompted twice)
airgapvault init

# Or with a keyfile for offline automation
airgapvault init --keyfile /path/to/master.key
```

### 2. Import an existing `.env` file
```bash
# Import into project "myapp", environment "dev", and securely remove the plaintext .env
airgapvault import myapp/dev .env --delete-source
```

### 3. Set, get, and list secrets
```bash
# Set inline
airgapvault set myapp/prod DATABASE_URL=postgres://user:pass@localhost:5432/app

# Set interactively (masked input, avoids shell history)
airgapvault set myapp/prod API_SECRET

# List projects, environments, or keys
airgapvault list
airgapvault list myapp
airgapvault list myapp/prod
airgapvault list myapp/prod --reveal

# Get a single secret (omits trailing newline when piped)
airgapvault get myapp/prod API_SECRET
```

### 4. Run your application without `.env`
```bash
airgapvault run -p myapp -e prod -- ./my-app --port 8080
```
`airgapvault run` decrypts the vault in memory, merges secrets into the child process environment (overriding any matching variables), forwards `stdin`/`stdout`/`stderr` and `SIGINT`/`SIGTERM`, and exits with the child process's exact exit code.

### 5. Remove, export, or rotate master passphrase
```bash
# Remove a single key
airgapvault rm myapp/dev OLD_KEY

# Remove an environment or project (prompts for confirmation; use -y to skip)
airgapvault rm myapp/dev
airgapvault rm myapp -y

# Manual fallback export to stdout
airgapvault export myapp/prod --format dotenv

# Change master passphrase / re-encrypt vault
airgapvault passwd
```

## Security Notes

- **Vault File Format (`AGV1`)**:
  `[4B Magic "AGV1"] [4B HeaderLen] [JSON Header] [AES-256-GCM Ciphertext + Tag]`
  The JSON header (version, Argon2id parameters, salt, nonce) is passed as Additional Authenticated Data (AAD) to AES-256-GCM so any tampering with metadata is rejected.
- **File Permissions**: Vault directories are created with `0700` and vault files with `0600`.
- **Shell History**: Prefer `airgapvault set <project>/<env> <KEY>` (interactive masked prompt) or `airgapvault import` instead of passing secret values on the command line.
- **Memory & Child Processes**: Master passphrases and decrypted vault JSON buffers are cleared (`clear()`) in memory after use. During `airgapvault run`, secrets are passed via environment variables to the child process (inherent to Unix process environments).
