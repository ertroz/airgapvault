package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	passphrase := []byte("super-secret-airgap-passphrase")
	plaintext := []byte(`{"version":1,"projects":{"app":{"environments":{"prod":{"API_KEY":"xyz"}}}}}`)

	encrypted, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongPassphraseRejected(t *testing.T) {
	passphrase := []byte("correct-passphrase")
	wrongPass := []byte("wrong-passphrase")
	plaintext := []byte("secret data")

	encrypted, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(encrypted, wrongPass)
	if !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("expected ErrInvalidPassphrase, got: %v", err)
	}
}

func TestEncryptProducesUniqueNoncesAndCiphertexts(t *testing.T) {
	passphrase := []byte("same-passphrase")
	plaintext := []byte("same-plaintext")

	enc1, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt 1 failed: %v", err)
	}
	enc2, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt 2 failed: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions of the same plaintext should not be identical")
	}
}

func TestDecryptRejectsTamperedData(t *testing.T) {
	passphrase := []byte("passphrase")
	plaintext := []byte("important secrets")

	encrypted, err := Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with ciphertext (last byte)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := Decrypt(tampered, passphrase); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("expected ErrInvalidPassphrase for tampered ciphertext, got %v", err)
	}

	// Tamper with header AAD (e.g. flip a byte inside JSON header)
	tamperedHeader := make([]byte, len(encrypted))
	copy(tamperedHeader, encrypted)
	headerLen := binary.BigEndian.Uint32(tamperedHeader[4:8])
	if headerLen > 10 {
		// Flip a byte in the middle of the JSON header
		tamperedHeader[8+int(headerLen)/2] ^= 0x01
		if _, err := Decrypt(tamperedHeader, passphrase); err == nil {
			t.Fatal("expected error for tampered header, got nil")
		}
	}

	// Tamper with magic bytes
	badMagic := make([]byte, len(encrypted))
	copy(badMagic, encrypted)
	badMagic[0] = 'X'
	if _, err := Decrypt(badMagic, passphrase); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected ErrInvalidFormat for bad magic, got %v", err)
	}
}
