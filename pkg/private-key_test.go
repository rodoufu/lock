package pkg

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	privateKey, err := NewRSARandomKey()
	assert.Nil(t, err)
	assert.NotNil(t, privateKey)

	message := []byte("simple message")
	var encrypted []byte
	publicKey := privateKey.PublicKey()
	encrypted, err = publicKey.Encrypt(message)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)

	var decrypted []byte
	decrypted, err = privateKey.Decrypt(encrypted)
	assert.Nil(t, err)
	assert.NotNil(t, decrypted)

	assert.Equal(t, message, decrypted)
}

func TestSignVerify(t *testing.T) {
	privateKey, err := NewRSARandomKey()
	assert.Nil(t, err)
	assert.NotNil(t, privateKey)

	message := []byte("simple message")
	var signed []byte
	signed, err = privateKey.Sign(message)
	assert.Nil(t, err)
	assert.NotNil(t, signed)

	publicKey := privateKey.PublicKey()
	assert.True(t, publicKey.Verify(message, signed))
}
