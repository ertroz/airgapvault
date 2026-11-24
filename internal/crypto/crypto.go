package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	magicBytes    = "AGV1"
	formatVersion = 1

	kdfArgon2id = "argon2id"
	cipherAES   = "aes-256-gcm"

	defaultArgon2Time    uint32 = 3
	defaultArgon2Memory  uint32 = 64 * 1024 // 64 MiB
	defaultArgon2Threads uint8  = 4
	keyLen                      = 32
	saltLen                     = 16
	nonceLen                    = 12
)

var (
	ErrInvalidFormat     = errors.New("invalid vault file format")
	ErrInvalidPassphrase = errors.New("decryption failed: invalid passphrase/keyfile or corrupted vault")
)

// Header holds non-sensitive cryptographic metadata for a vault file.
type Header struct {
	Version       int    `json:"version"`
	KDF           string `json:"kdf"`
	Argon2Time    uint32 `json:"argon2_time"`
	Argon2Memory  uint32 `json:"argon2_memory"`
	Argon2Threads uint8  `json:"argon2_threads"`
	Salt          []byte `json:"salt"`
	Cipher        string `json:"cipher"`
	Nonce         []byte `json:"nonce"`
}

// Encrypt encrypts plaintext using Argon2id + AES-256-GCM with a fresh random
// salt and nonce, binding the serialized header as Additional Authenticated Data (AAD).
func Encrypt(plaintext, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase or keyfile must not be empty")
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	hdr := Header{
		Version:       formatVersion,
		KDF:           kdfArgon2id,
		Argon2Time:    defaultArgon2Time,
		Argon2Memory:  defaultArgon2Memory,
		Argon2Threads: defaultArgon2Threads,
		Salt:          salt,
		Cipher:        cipherAES,
		Nonce:         nonce,
	}

	headerBytes, err := json.Marshal(hdr)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	key := argon2.IDKey(passphrase, salt, hdr.Argon2Time, hdr.Argon2Memory, hdr.Argon2Threads, keyLen)
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, headerBytes)

	out := make([]byte, 0, len(magicBytes)+4+len(headerBytes)+len(ciphertext))
	out = append(out, magicBytes...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(headerBytes)))
	out = append(out, lenBuf[:]...)
	out = append(out, headerBytes...)
	out = append(out, ciphertext...)

	return out, nil
}

// Decrypt verifies the vault format, derives the key with Argon2id, and
// decrypts the AES-256-GCM ciphertext while authenticating the header as AAD.
func Decrypt(data, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase or keyfile must not be empty")
	}

	if len(data) < len(magicBytes)+4 {
		return nil, ErrInvalidFormat
	}

	if string(data[:len(magicBytes)]) != magicBytes {
		return nil, ErrInvalidFormat
	}

	headerLen := binary.BigEndian.Uint32(data[len(magicBytes) : len(magicBytes)+4])
	headerStart := len(magicBytes) + 4
	headerEnd := headerStart + int(headerLen)
	if headerLen == 0 || headerEnd > len(data) || headerEnd < headerStart {
		return nil, ErrInvalidFormat
	}

	headerBytes := data[headerStart:headerEnd]
	var hdr Header
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}

	if hdr.Version != formatVersion || hdr.KDF != kdfArgon2id || hdr.Cipher != cipherAES {
		return nil, ErrInvalidFormat
	}
	if len(hdr.Salt) < 8 || len(hdr.Nonce) != nonceLen {
		return nil, ErrInvalidFormat
	}
	if hdr.Argon2Time < 1 || hdr.Argon2Memory < 1024 || hdr.Argon2Threads < 1 {
		return nil, ErrInvalidFormat
	}

	key := argon2.IDKey(passphrase, hdr.Salt, hdr.Argon2Time, hdr.Argon2Memory, hdr.Argon2Threads, keyLen)
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := data[headerEnd:]
	plaintext, err := gcm.Open(nil, hdr.Nonce, ciphertext, headerBytes)
	if err != nil {
		return nil, ErrInvalidPassphrase
	}

	return plaintext, nil
}
