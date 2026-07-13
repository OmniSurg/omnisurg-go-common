package crypto_test

import (
	"bytes"
	"testing"

	"github.com/OmniSurg/omnisurg-go-common/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDEKLength(t *testing.T) {
	dek, err := crypto.GenerateDEK()
	require.NoError(t, err)
	assert.Len(t, dek, crypto.KeySize)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dek, err := crypto.GenerateDEK()
	require.NoError(t, err)
	c, err := crypto.NewCipher(dek)
	require.NoError(t, err)

	plain := []byte("reception@kawome.test")
	blob, err := c.Encrypt(plain)
	require.NoError(t, err)
	assert.NotEqual(t, plain, blob, "ciphertext must differ from plaintext")

	out, err := c.Decrypt(blob)
	require.NoError(t, err)
	assert.Equal(t, plain, out)
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	dek, _ := crypto.GenerateDEK()
	c, _ := crypto.NewCipher(dek)
	a, err := c.Encrypt([]byte("same"))
	require.NoError(t, err)
	b, err := c.Encrypt([]byte("same"))
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a, b), "random nonce must make ciphertexts differ")
}

func TestNewCipherRejectsWrongKeyLength(t *testing.T) {
	_, err := crypto.NewCipher([]byte("too-short"))
	require.Error(t, err)
}

func TestDecryptRejectsTampered(t *testing.T) {
	dek, _ := crypto.GenerateDEK()
	c, _ := crypto.NewCipher(dek)
	blob, _ := c.Encrypt([]byte("secret"))
	blob[len(blob)-1] ^= 0xFF
	_, err := c.Decrypt(blob)
	require.Error(t, err)
}

func TestWrapUnwrapKey(t *testing.T) {
	kek, _ := crypto.GenerateDEK()
	dek, _ := crypto.GenerateDEK()
	wrapped, err := crypto.WrapKey(kek, dek)
	require.NoError(t, err)
	assert.NotEqual(t, dek, wrapped)

	unwrapped, err := crypto.UnwrapKey(kek, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped)
}

func TestUnwrapWithWrongKEKFails(t *testing.T) {
	kek1, _ := crypto.GenerateDEK()
	kek2, _ := crypto.GenerateDEK()
	dek, _ := crypto.GenerateDEK()
	wrapped, _ := crypto.WrapKey(kek1, dek)
	_, err := crypto.UnwrapKey(kek2, wrapped)
	require.Error(t, err)
}

func TestBlindIndexIsDeterministic(t *testing.T) {
	key, _ := crypto.GenerateDEK()
	a := crypto.BlindIndex(key, "reception@example.test")
	b := crypto.BlindIndex(key, "reception@example.test")
	assert.Equal(t, a, b)
	assert.NotEmpty(t, a)
}

func TestBlindIndexDiffersByValueAndKey(t *testing.T) {
	k1, _ := crypto.GenerateDEK()
	k2, _ := crypto.GenerateDEK()
	assert.NotEqual(t, crypto.BlindIndex(k1, "a"), crypto.BlindIndex(k1, "b"))
	assert.NotEqual(t, crypto.BlindIndex(k1, "a"), crypto.BlindIndex(k2, "a"))
}

func TestDeriveSubkeyStableAndDistinct(t *testing.T) {
	master, _ := crypto.GenerateDEK()
	a, err := crypto.DeriveSubkey(master, "email-blind-index")
	require.NoError(t, err)
	b, err := crypto.DeriveSubkey(master, "email-blind-index")
	require.NoError(t, err)
	other, err := crypto.DeriveSubkey(master, "phone-blind-index")
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.Len(t, a, crypto.KeySize)
	assert.NotEqual(t, a, other)
}
