package pkg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

type PrivateKey interface {
	AsBytes() ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	Sign([]byte) ([]byte, error)
	SignDigest([]byte, DigestMethod) ([]byte, error)
	PublicKey() PublicKey
}

type rsaPrivateKey struct {
	key  *rsa.PrivateKey
	hash crypto.Hash
}

func (r *rsaPrivateKey) AsBytes() ([]byte, error) {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(r.key),
		},
	), nil
}

func (r *rsaPrivateKey) Sign(message []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, r.key, crypto.Hash(0), message)
}

func (r *rsaPrivateKey) SignDigest(message []byte, method DigestMethod) ([]byte, error) {
	if hashed, err := method.Digest(message); err == nil {
		return r.Sign(hashed)
	} else {
		return nil, err
	}
}

func (r *rsaPrivateKey) Decrypt(message []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, r.key, message, nil)
}

func (r *rsaPrivateKey) PublicKey() PublicKey {
	return &rsaPublicKey{
		key: &r.key.PublicKey,
	}
}

func (r *rsaPrivateKey) Signs(message []byte, method DigestMethod) ([]byte, error) {
	if msgHashSum, err := method.Digest(message); err != nil {
		return nil, err
	} else {
		return rsa.SignPSS(rand.Reader, r.key, crypto.SHA256, msgHashSum, nil)
	}
}

func NewRSARandomKey() (PrivateKey, error) {
	if pk, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, err
	} else {
		key := &rsaPrivateKey{
			key:  pk,
			hash: crypto.SHA256,
		}
		return key, nil
	}
}

func NewPrivateKey(priv []byte) (PrivateKey, error) {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		if b, err = x509.DecryptPEMBlock(block, nil); err != nil {
			return nil, err
		}
	}
	var key *rsa.PrivateKey
	if key, err = x509.ParsePKCS1PrivateKey(b); err != nil {
		return nil, err
	}

	return &rsaPrivateKey{
		key:  key,
		hash: crypto.SHA256,
	}, nil
}
