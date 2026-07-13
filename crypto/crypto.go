// Package crypto provides the OmniSurg column encryption primitives: AES-256-GCM
// authenticated encryption, KEK wrapping of data encryption keys (envelope
// encryption), HKDF subkey derivation, and an HMAC blind index for equality
// lookups on encrypted columns. Every service that stores PII (national_id,
// phone, email) uses these so the encryption scheme is identical platform wide.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeySize is the AES-256 key length in bytes. DEKs and KEKs are this size.
const KeySize = 32

// nonceSize is the GCM standard nonce length.
const nonceSize = 12

// GenerateDEK returns a fresh cryptographically random 256 bit key.
func GenerateDEK() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("crypto.GenerateDEK: read random: %w", err)
	}
	return k, nil
}

// Cipher performs AES-256-GCM authenticated encryption with a fixed key.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from a 32 byte key. The key is retained inside the
// Cipher for its lifetime; callers should not assume the passed slice is wiped.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto.NewCipher: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewCipher: new aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewCipher: new gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext and returns nonce concatenated with the ciphertext.
// A fresh random nonce is used per call, so identical plaintext yields
// different output, which prevents an attacker correlating equal values.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto.Encrypt: read nonce: %w", err)
	}
	sealed := c.aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// Decrypt opens the nonce concatenated ciphertext produced by Encrypt. It
// returns an error if authentication fails (tampering or wrong key).
func (c *Cipher) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < nonceSize {
		return nil, errors.New("crypto.Decrypt: ciphertext too short")
	}
	nonce, sealed := blob[:nonceSize], blob[nonceSize:]
	out, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto.Decrypt: open: %w", err)
	}
	return out, nil
}

// WrapKey encrypts a DEK under a KEK using the same AEAD construction. The
// wrapped DEK is what gets stored in the database; the KEK never is.
func WrapKey(kek, dek []byte) ([]byte, error) {
	c, err := NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("crypto.WrapKey: %w", err)
	}
	return c.Encrypt(dek)
}

// UnwrapKey decrypts a wrapped DEK under a KEK.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	c, err := NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("crypto.UnwrapKey: %w", err)
	}
	return c.Decrypt(wrapped)
}

// DeriveSubkey derives a 32 byte subkey from a master key using HKDF-SHA256
// with the given info label. Use it to derive distinct keys for distinct
// purposes (eg the email blind index key) from a single DEK.
func DeriveSubkey(master []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, master, nil, []byte(info))
	out := make([]byte, KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("crypto.DeriveSubkey: %w", err)
	}
	return out, nil
}

// BlindIndex returns a deterministic hex HMAC-SHA256 of value under key, for
// equality lookups on encrypted columns (eg login by email). The key must be
// distinct from any data encryption key; derive it with DeriveSubkey.
func BlindIndex(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
